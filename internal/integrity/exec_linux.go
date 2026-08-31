//go:build linux

package integrity

import (
	"errors"
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	ExecutableFD  = 3
	DirectoryFD   = 4
	InterpreterFD = 5
)

// ExecVerified replaces the current process with the executable referenced by
// fd. /proc/self/fd resolves the already-open file description, preventing a
// substitution of the originally supplied executable pathname.
func ExecVerified(fd int, argv, environment []string) error {
	if fd < 3 || len(argv) == 0 {
		return errors.New("invalid verified execution descriptor")
	}
	return unix.Exec("/proc/self/fd/"+strconv.Itoa(fd), argv, environment)
}

// ExecPinned enters the verified working directory and executes either the
// verified executable or, for a script, the verified interpreter with the
// verified script descriptor. No approved filesystem object is reopened by
// its original pathname.
func ExecPinned(executableFD, directoryFD, interpreterFD int, executablePath string, arguments, environment []string, interpreterPath string, interpreterArgument *string) error {
	if executableFD < 3 || directoryFD < 3 || executablePath == "" {
		return errors.New("invalid pinned execution descriptors")
	}
	if err := unix.Fchdir(directoryFD); err != nil {
		return err
	}
	if interpreterPath == "" {
		return ExecVerified(executableFD, append([]string{executablePath}, arguments...), environment)
	}
	if interpreterFD < 3 {
		return errors.New("missing verified interpreter descriptor")
	}
	argv := []string{interpreterPath}
	if interpreterArgument != nil {
		argv = append(argv, *interpreterArgument)
	}
	argv = append(argv, "/proc/self/fd/"+strconv.Itoa(executableFD))
	argv = append(argv, arguments...)
	return ExecVerified(interpreterFD, argv, environment)
}
