//go:build linux

package integrity

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"shudo.local/shudo/internal/model"
)

const safePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
const maxSafeInteger = uint64(1<<53 - 1)

func ResolveExecutable(value, cwd string) (string, error) {
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", errors.New("executable is empty or invalid")
	}
	var candidate string
	if strings.ContainsRune(value, '/') {
		candidate = value
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(cwd, candidate)
		}
	} else {
		for _, directory := range strings.Split(safePath, ":") {
			path := filepath.Join(directory, value)
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
				candidate = path
				break
			}
		}
	}
	if candidate == "" {
		return "", fmt.Errorf("executable %q not found in safe PATH", value)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(resolved) {
		return "", errors.New("resolved executable is not absolute")
	}
	return resolved, nil
}

func InspectExecutable(path string) (model.FileMetadata, error) {
	metadata, _, _, err := InspectExecutableAndInterpreter(path, 0)
	return metadata, err
}

// InspectExecutableAndInterpreter reads executable metadata and any shebang
// from one open file description, so a path swap cannot make the recorded
// interpreter describe different bytes from the recorded executable.
func InspectExecutableAndInterpreter(path string, maxBytes int64) (model.FileMetadata, *model.FileMetadata, *string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return model.FileMetadata{}, nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	metadata, err := inspectExecutableFile(file, path, maxBytes)
	if err != nil {
		return model.FileMetadata{}, nil, nil, err
	}
	interpreterPath, argument, script, err := inspectShebang(file)
	if err != nil {
		return model.FileMetadata{}, nil, nil, err
	}
	if !script {
		return metadata, nil, nil, nil
	}
	resolved, err := filepath.EvalSymlinks(interpreterPath)
	if err != nil {
		return model.FileMetadata{}, nil, nil, err
	}
	interpreter, nestedScript, err := inspectExecutablePath(resolved, maxBytes)
	if err != nil {
		return model.FileMetadata{}, nil, nil, err
	}
	if nestedScript {
		return model.FileMetadata{}, nil, nil, errors.New("script interpreters are not supported")
	}
	return metadata, &interpreter, argument, nil
}

func inspectExecutablePath(path string, maxBytes int64) (model.FileMetadata, bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return model.FileMetadata{}, false, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	metadata, err := inspectExecutableFile(file, path, maxBytes)
	if err != nil {
		return model.FileMetadata{}, false, err
	}
	_, _, script, err := inspectShebang(file)
	return metadata, script, err
}

func inspectExecutableFile(file *os.File, path string, maxBytes int64) (model.FileMetadata, error) {
	fd := int(file.Fd())
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return model.FileMetadata{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0111 == 0 {
		return model.FileMetadata{}, errors.New("executable must be an executable regular file")
	}
	if maxBytes > 0 && stat.Size > maxBytes {
		return model.FileMetadata{}, fmt.Errorf("executable exceeds configured size limit")
	}
	if stat.Dev > maxSafeInteger || stat.Ino > maxSafeInteger || stat.Size < 0 || uint64(stat.Size) > maxSafeInteger {
		return model.FileMetadata{}, errors.New("executable metadata exceeds protocol integer range")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return model.FileMetadata{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return model.FileMetadata{}, err
	}
	device, inode, size := uint64(stat.Dev), stat.Ino, uint64(stat.Size)
	owner, mode := stat.Uid, uint32(stat.Mode)
	mtime, ctime := timestamp(stat.Mtim), timestamp(stat.Ctim)
	return model.FileMetadata{
		Path: path, Device: &device, Inode: &inode, Size: &size, OwnerUID: &owner,
		Mode: &mode, MtimeNS: &mtime, CtimeNS: &ctime, SHA256: hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

func VerifyExecutable(expected model.FileMetadata) error {
	file, err := OpenVerifiedExecutable(expected)
	if file != nil {
		_ = file.Close()
	}
	return err
}

// OpenVerifiedExecutable returns the exact file description that was checked.
// Callers must execute this descriptor rather than reopening expected.Path.
func OpenVerifiedExecutable(expected model.FileMetadata) (*os.File, error) {
	fd, err := unix.Open(expected.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), expected.Path)
	actual, err := inspectExecutableFile(file, expected.Path, 0)
	if err != nil {
		file.Close()
		return nil, err
	}
	if expected.Device == nil || expected.Inode == nil || expected.Size == nil ||
		expected.OwnerUID == nil || expected.Mode == nil || expected.MtimeNS == nil || expected.CtimeNS == nil ||
		*expected.Device != *actual.Device || *expected.Inode != *actual.Inode ||
		*expected.Size != *actual.Size || *expected.OwnerUID != *actual.OwnerUID ||
		*expected.Mode != *actual.Mode || *expected.MtimeNS != *actual.MtimeNS ||
		*expected.CtimeNS != *actual.CtimeNS || expected.SHA256 != actual.SHA256 {
		file.Close()
		return nil, errors.New("executable integrity metadata changed")
	}
	return file, nil
}

func InspectDirectory(path string) (model.WorkingDirectoryMetadata, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return model.WorkingDirectoryMetadata{}, err
	}
	if !filepath.IsAbs(resolved) {
		return model.WorkingDirectoryMetadata{}, errors.New("working directory is not absolute")
	}
	var stat unix.Stat_t
	if err := unix.Stat(resolved, &stat); err != nil {
		return model.WorkingDirectoryMetadata{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Dev > maxSafeInteger || stat.Ino > maxSafeInteger {
		return model.WorkingDirectoryMetadata{}, errors.New("invalid working directory")
	}
	return model.WorkingDirectoryMetadata{
		Path: resolved, Device: uint64(stat.Dev), Inode: stat.Ino, OwnerUID: stat.Uid,
		Mode: uint32(stat.Mode), MtimeNS: timestamp(stat.Mtim), CtimeNS: timestamp(stat.Ctim),
	}, nil
}

func VerifyDirectory(expected model.WorkingDirectoryMetadata) error {
	file, err := OpenVerifiedDirectory(expected)
	if file != nil {
		_ = file.Close()
	}
	return err
}

// OpenVerifiedDirectory returns a pinned directory descriptor. Execution must
// fchdir to this descriptor instead of reopening expected.Path.
func OpenVerifiedDirectory(expected model.WorkingDirectoryMetadata) (*os.File, error) {
	fd, err := unix.Open(expected.Path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), expected.Path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		file.Close()
		return nil, err
	}
	actual := model.WorkingDirectoryMetadata{
		Path: expected.Path, Device: uint64(stat.Dev), Inode: stat.Ino, OwnerUID: stat.Uid,
		Mode: uint32(stat.Mode), MtimeNS: timestamp(stat.Mtim), CtimeNS: timestamp(stat.Ctim),
	}
	if actual != expected {
		file.Close()
		return nil, errors.New("working directory identity changed")
	}
	return file, nil
}

func InspectInterpreter(executable string) (*model.FileMetadata, bool, error) {
	file, err := os.Open(executable)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	path, _, script, err := inspectShebang(file)
	if err != nil || !script {
		return nil, script, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, true, err
	}
	metadata, err := InspectExecutable(resolved)
	return &metadata, true, err
}

func inspectShebang(file *os.File) (string, *string, bool, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", nil, false, err
	}
	reader := bufio.NewReader(io.LimitReader(file, 4096))
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "#!") {
		return "", nil, false, nil
	}
	value := strings.TrimSpace(strings.TrimPrefix(line, "#!"))
	if value == "" {
		return "", nil, true, errors.New("script shebang must name an absolute interpreter")
	}
	index := strings.IndexAny(value, " \t")
	path := value
	var argument *string
	if index >= 0 {
		path = value[:index]
		remainder := strings.TrimSpace(value[index:])
		if remainder != "" {
			argument = &remainder
		}
	}
	if !filepath.IsAbs(path) {
		return "", nil, true, errors.New("script shebang must name an absolute interpreter")
	}
	return path, argument, true, nil
}

func SanitizeEnvironment(overrides map[string]string, allowed []string) ([]string, error) {
	environment := map[string]string{
		"PATH": safePath, "HOME": "/root", "LANG": "C.UTF-8",
	}
	if len(allowed) != 0 || len(overrides) != 0 {
		return nil, errors.New("environment overrides are not supported")
	}
	result := make([]string, 0, len(environment))
	for key, value := range environment {
		result = append(result, key+"="+value)
	}
	return result, nil
}

func Risk(executable string, argv []string, script bool, env map[string]string) model.RiskMetadata {
	base := filepath.Base(executable)
	interpreters := map[string]bool{
		"bash": true, "sh": true, "zsh": true, "python": true, "python3": true,
		"node": true, "perl": true, "ruby": true,
	}
	interpreter := interpreters[base]
	warnings := []string{}
	if interpreter {
		warnings = append(warnings, "Interpreter may execute dynamic code")
	}
	if script {
		warnings = append(warnings, "Script contents may reference mutable dependencies")
	}
	if len(env) > 0 {
		warnings = append(warnings, "Environment overrides change execution context")
	}
	return model.RiskMetadata{
		Shell: base == "sh" || base == "bash" || base == "zsh", Interpreter: interpreter,
		Script: script, EnvironmentOverrides: len(env) > 0, Warnings: warnings,
	}
}

func timestamp(value unix.Timespec) string {
	return fmt.Sprintf("%d", value.Sec*1_000_000_000+value.Nsec)
}
