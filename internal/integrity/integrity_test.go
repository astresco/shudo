//go:build linux

package integrity

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestExecVerifiedHelper(t *testing.T) {
	switch os.Getenv("SHUDO_TEST_EXEC_MODE") {
	case "verified-output":
		if err := ExecVerified(3, []string{"/usr/bin/printf", "verified"}, []string{"PATH=" + safePath}); err != nil {
			t.Fatal(err)
		}
	case "pinned-original":
		if err := ExecVerified(3, []string{"approved-tool", os.Getenv("SHUDO_TEST_MARKER")}, []string{"PATH=" + safePath}); err != nil {
			t.Fatal(err)
		}
	case "pinned-script":
		if err := ExecPinned(ExecutableFD, DirectoryFD, InterpreterFD, "approved-script", []string{"argument"}, []string{"PATH=" + safePath}, "/bin/sh", nil); err != nil {
			t.Fatal(err)
		}
	case "pinned-cwd":
		if err := ExecPinned(ExecutableFD, DirectoryFD, -1, "/usr/bin/touch", []string{"marker"}, []string{"PATH=" + safePath}, "", nil); err != nil {
			t.Fatal(err)
		}
	default:
		return
	}
}

func TestVerifiedDescriptorExecution(t *testing.T) {
	metadata, err := InspectExecutable("/usr/bin/printf")
	if err != nil {
		t.Fatal(err)
	}
	file, err := OpenVerifiedExecutable(metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	command := exec.Command(os.Args[0], "-test.run=TestExecVerifiedHelper")
	command.Env = append(os.Environ(), "SHUDO_TEST_EXEC_MODE=verified-output")
	command.ExtraFiles = []*os.File{file}
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != "verified" {
		t.Fatalf("got %q", output)
	}
}

func TestDangerousEnvironmentIsRejected(t *testing.T) {
	if _, err := SanitizeEnvironment(map[string]string{"LD_PRELOAD": "/tmp/evil.so"}, []string{"LD_PRELOAD"}); err == nil {
		t.Fatal("LD_PRELOAD was accepted")
	}
	if _, err := SanitizeEnvironment(map[string]string{"SHUDO_TEST": "yes"}, nil); err == nil {
		t.Fatal("environment override without an allowlist was accepted")
	}
	if _, err := SanitizeEnvironment(map[string]string{"SHUDO_TEST": "yes"}, []string{"SHUDO_TEST"}); err == nil {
		t.Fatal("allowlisted environment override was accepted")
	}
}

func TestExecutableMutationIsDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("first"), 0755); err != nil {
		t.Fatal(err)
	}
	metadata, err := InspectExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("second"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecutable(metadata); err == nil {
		t.Fatal("mutated executable passed integrity verification")
	}
}

func TestResolveExecutable(t *testing.T) {
	resolved, err := ResolveExecutable("id", "/")
	if err != nil || !filepath.IsAbs(resolved) || filepath.Base(resolved) != "id" {
		t.Fatalf("safe PATH resolution failed: %q %v", resolved, err)
	}
	directory := t.TempDir()
	tool := filepath.Join(directory, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(tool, link); err != nil {
		t.Fatal(err)
	}
	resolved, err = ResolveExecutable(link, "/")
	if err != nil || resolved != tool {
		t.Fatalf("symlink resolution failed: %q %v", resolved, err)
	}
	for _, value := range []string{"", "bad\x00name", "definitely-not-a-shudo-command"} {
		if _, err := ResolveExecutable(value, directory); err == nil {
			t.Fatalf("invalid executable %q resolved", value)
		}
	}
	if _, err := ResolveExecutable(filepath.Join(directory, "missing"), "/"); err == nil {
		t.Fatal("missing absolute executable resolved")
	}
}

func TestResolveRelativeExecutableAndDirectory(t *testing.T) {
	directory := t.TempDir()
	tool := filepath.Join(directory, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(directory)
	resolved, err := ResolveExecutable("./tool", ".")
	if err == nil || resolved != "" {
		t.Fatalf("relative cwd unexpectedly produced an absolute executable: %q %v", resolved, err)
	}
	if _, err := InspectDirectory("."); err == nil {
		t.Fatal("relative working directory was accepted")
	}
}

func TestExecutableInspectionAndVerificationEdges(t *testing.T) {
	directory := t.TempDir()
	if _, err := InspectExecutable(directory); err == nil {
		t.Fatal("directory accepted as executable")
	}
	nonExecutable := filepath.Join(directory, "plain")
	if err := os.WriteFile(nonExecutable, []byte("plain"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectExecutable(nonExecutable); err == nil {
		t.Fatal("non-executable file accepted")
	}
	if _, err := InspectExecutable(filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing executable accepted")
	}
	metadata, err := InspectExecutable("/usr/bin/id")
	if err != nil {
		t.Fatal(err)
	}
	file, err := OpenVerifiedExecutable(metadata)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := VerifyExecutable(metadata); err != nil {
		t.Fatal(err)
	}
	incomplete := metadata
	incomplete.Device = nil
	if _, err := OpenVerifiedExecutable(incomplete); err == nil {
		t.Fatal("incomplete metadata accepted")
	}
	missing := metadata
	missing.Path = filepath.Join(directory, "missing")
	if _, err := OpenVerifiedExecutable(missing); err == nil {
		t.Fatal("missing verified executable accepted")
	}
	closed, err := os.Open("/usr/bin/id")
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectExecutableFile(closed, "/usr/bin/id", 0); err == nil {
		t.Fatal("closed file descriptor was inspected")
	}
	pathOnlyFD, err := unix.Open("/usr/bin/id", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	pathOnly := os.NewFile(uintptr(pathOnlyFD), "/usr/bin/id")
	defer pathOnly.Close()
	if _, err := inspectExecutableFile(pathOnly, "/usr/bin/id", 0); err == nil {
		t.Fatal("unreadable executable descriptor was hashed")
	}

	replacedPath := filepath.Join(directory, "replaced")
	if err := os.WriteFile(replacedPath, []byte("executable"), 0755); err != nil {
		t.Fatal(err)
	}
	replaced, err := InspectExecutable(replacedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(replacedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(replacedPath, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerifiedExecutable(replaced); err == nil {
		t.Fatal("directory replacement passed executable verification")
	}
}

func TestDirectoryInspectionAndVerification(t *testing.T) {
	directory := t.TempDir()
	link := filepath.Join(t.TempDir(), "directory-link")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	metadata, err := InspectDirectory(link)
	if err != nil || metadata.Path != directory {
		t.Fatalf("directory inspection failed: %#v %v", metadata, err)
	}
	if err := VerifyDirectory(metadata); err != nil {
		t.Fatal(err)
	}
	changed := metadata
	changed.Inode++
	if err := VerifyDirectory(changed); err == nil {
		t.Fatal("changed directory metadata accepted")
	}
	missing := metadata
	missing.Path = filepath.Join(directory, "missing")
	if err := VerifyDirectory(missing); err == nil {
		t.Fatal("missing working directory passed verification")
	}
	for _, value := range []string{"relative", filepath.Join(directory, "missing")} {
		if _, err := InspectDirectory(value); err == nil {
			t.Fatalf("invalid directory %q accepted", value)
		}
	}
	file := filepath.Join(directory, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectDirectory(file); err == nil {
		t.Fatal("file accepted as directory")
	}
}

func TestInterpreterInspection(t *testing.T) {
	directory := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	metadata, script, err := InspectInterpreter("/usr/bin/id")
	if err != nil || script || metadata != nil {
		t.Fatalf("binary identified as script: %#v %v %v", metadata, script, err)
	}
	metadata, script, err = InspectInterpreter(write("script", "#!/bin/sh\nexit 0\n"))
	if err != nil || !script || metadata == nil {
		t.Fatalf("valid script rejected: %#v %v %v", metadata, script, err)
	}
	for index, body := range []string{"#!\n", "#!relative\n", "#!/definitely/missing/interpreter\n"} {
		if _, script, err := InspectInterpreter(write(fmt.Sprintf("invalid-%d", index), body)); !script || err == nil {
			t.Fatalf("invalid shebang accepted: %q", body)
		}
	}
	if _, _, err := InspectInterpreter(filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing executable inspected")
	}
}

func TestEnvironmentValidationEdges(t *testing.T) {
	invalid := []map[string]string{
		{"": "x"},
		{"A=B": "x"},
		{"TERM": "bad\x00value"},
	}
	for _, overrides := range invalid {
		if _, err := SanitizeEnvironment(overrides, []string{"TERM", "A=B", ""}); err == nil {
			t.Fatalf("invalid environment accepted: %#v", overrides)
		}
	}
	environment, err := SanitizeEnvironment(nil, nil)
	if err != nil || len(environment) != 3 {
		t.Fatalf("safe baseline missing: %#v %v", environment, err)
	}
}

func TestRiskMetadata(t *testing.T) {
	risk := Risk("/bin/bash", []string{"-lc", "true"}, true, map[string]string{"TERM": "x"})
	if !risk.Shell || !risk.Interpreter || !risk.Script || !risk.EnvironmentOverrides || len(risk.Warnings) != 3 {
		t.Fatalf("risk metadata incomplete: %#v", risk)
	}
	plain := Risk("/usr/bin/id", nil, false, nil)
	if plain.Shell || plain.Interpreter || plain.Script || len(plain.Warnings) != 0 {
		t.Fatalf("plain executable marked risky: %#v", plain)
	}
}

func TestExecVerifiedRejectsInvalidArguments(t *testing.T) {
	for _, test := range []struct {
		fd   int
		argv []string
	}{{2, []string{"id"}}, {3, nil}} {
		if err := ExecVerified(test.fd, test.argv, nil); err == nil {
			t.Fatalf("invalid execution accepted: %#v", test)
		}
	}
	if err := ExecVerified(999999, []string{"missing"}, nil); err == nil {
		t.Fatal("invalid open descriptor was executed")
	}
}

func TestPinnedScriptInspectionAndExecution(t *testing.T) {
	directory := t.TempDir()
	interpreterPath := filepath.Join(directory, "interpreter")
	interpreterBytes, err := os.ReadFile("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(interpreterPath, interpreterBytes, 0755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(directory, "script")
	if err := os.WriteFile(script, []byte("#!"+interpreterPath+"\nprintf '%s:%s' \"$PWD\" \"$1\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	metadata, interpreter, argument, err := InspectExecutableAndInterpreter(script, 256*1024*1024)
	if err != nil || interpreter == nil || argument != nil {
		t.Fatalf("script inspection failed: %#v %#v %v", interpreter, argument, err)
	}
	executableFile, err := OpenVerifiedExecutable(metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer executableFile.Close()
	directoryMetadata, err := InspectDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	directoryFile, err := OpenVerifiedDirectory(directoryMetadata)
	if err != nil {
		t.Fatal(err)
	}
	defer directoryFile.Close()
	interpreterFile, err := OpenVerifiedExecutable(*interpreter)
	if err != nil {
		t.Fatal(err)
	}
	defer interpreterFile.Close()
	if err := os.Rename(interpreterPath, interpreterPath+"-approved"); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.ReadFile("/usr/bin/false")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(interpreterPath, replacement, 0755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=TestExecVerifiedHelper")
	command.Env = append(os.Environ(), "SHUDO_TEST_EXEC_MODE=pinned-script")
	command.ExtraFiles = []*os.File{executableFile, directoryFile, interpreterFile}
	output, err := command.Output()
	if err != nil || string(output) != directory+":argument" {
		t.Fatalf("pinned script failed: %q %v", output, err)
	}

	withArgument := filepath.Join(directory, "argument-script")
	if err := os.WriteFile(withArgument, []byte("#!/bin/sh -e\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	_, _, shebangArgument, err := InspectExecutableAndInterpreter(withArgument, 256*1024*1024)
	if err != nil || shebangArgument == nil || *shebangArgument != "-e" {
		t.Fatalf("shebang argument lost: %#v %v", shebangArgument, err)
	}
	if _, _, _, err := InspectExecutableAndInterpreter(withArgument, 1); err == nil {
		t.Fatal("executable size limit was not enforced")
	}
}

func TestPinnedWorkingDirectorySurvivesReplacement(t *testing.T) {
	parent := t.TempDir()
	working := filepath.Join(parent, "working")
	if err := os.Mkdir(working, 0700); err != nil {
		t.Fatal(err)
	}
	directoryMetadata, err := InspectDirectory(working)
	if err != nil {
		t.Fatal(err)
	}
	directoryFile, err := OpenVerifiedDirectory(directoryMetadata)
	if err != nil {
		t.Fatal(err)
	}
	defer directoryFile.Close()
	executableMetadata, err := InspectExecutable("/usr/bin/touch")
	if err != nil {
		t.Fatal(err)
	}
	executableFile, err := OpenVerifiedExecutable(executableMetadata)
	if err != nil {
		t.Fatal(err)
	}
	defer executableFile.Close()
	approvedDirectory := working + "-approved"
	if err := os.Rename(working, approvedDirectory); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(working, 0700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=TestExecVerifiedHelper")
	command.Env = append(os.Environ(), "SHUDO_TEST_EXEC_MODE=pinned-cwd")
	command.ExtraFiles = []*os.File{executableFile, directoryFile}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("pinned cwd execution failed: %v: %s", err, output)
	}
	if _, err := os.Stat(filepath.Join(approvedDirectory, "marker")); err != nil {
		t.Fatalf("approved directory was not used: %v", err)
	}
	if _, err := os.Stat(filepath.Join(working, "marker")); !os.IsNotExist(err) {
		t.Fatalf("replacement working directory was used: %v", err)
	}
}

func TestPinnedExecutionRejectsInvalidDescriptorsAndNestedInterpreter(t *testing.T) {
	if err := ExecPinned(2, 4, -1, "x", nil, nil, "", nil); err == nil {
		t.Fatal("invalid executable descriptor accepted")
	}
	if err := ExecPinned(3, 999999, -1, "x", nil, nil, "", nil); err == nil {
		t.Fatal("invalid directory descriptor accepted")
	}
	directory := t.TempDir()
	directoryMetadata, err := InspectDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	directoryFile, err := OpenVerifiedDirectory(directoryMetadata)
	if err != nil {
		t.Fatal(err)
	}
	defer directoryFile.Close()
	originalFD, err := unix.Open(".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(originalFD)
	defer func() { _ = unix.Fchdir(originalFD) }()
	if err := ExecPinned(999999, int(directoryFile.Fd()), -1, "/missing", nil, nil, "", nil); err == nil {
		t.Fatal("invalid pinned binary descriptor executed")
	}
	if err := ExecPinned(3, int(directoryFile.Fd()), -1, "script", nil, nil, "/bin/sh", nil); err == nil {
		t.Fatal("missing interpreter descriptor accepted")
	}
	argument := "-e"
	if err := ExecPinned(3, int(directoryFile.Fd()), 999999, "script", nil, nil, "/bin/sh", &argument); err == nil {
		t.Fatal("invalid pinned interpreter descriptor executed")
	}
	interpreter := filepath.Join(directory, "interpreter")
	if err := os.WriteFile(interpreter, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(directory, "script")
	if err := os.WriteFile(script, []byte("#!"+interpreter+"\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := InspectExecutableAndInterpreter(script, 256*1024*1024); err == nil {
		t.Fatal("nested script interpreter was accepted")
	}
	missingInterpreter := filepath.Join(directory, "missing-interpreter-script")
	if err := os.WriteFile(missingInterpreter, []byte("#!/definitely/missing/interpreter\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := InspectExecutableAndInterpreter(missingInterpreter, 256*1024*1024); err == nil {
		t.Fatal("missing interpreter was accepted")
	}
	if _, _, _, err := InspectExecutableAndInterpreter(filepath.Join(directory, "missing"), 256*1024*1024); err == nil {
		t.Fatal("missing executable was inspected")
	}
	directoryInterpreter := filepath.Join(directory, "directory-interpreter")
	if err := os.WriteFile(directoryInterpreter, []byte("#!"+directory+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := InspectExecutableAndInterpreter(directoryInterpreter, 256*1024*1024); err == nil {
		t.Fatal("directory shebang interpreter was accepted")
	}
}
