package commands

import (
	"errors"
	"fmt"
)

// ExitStatus attaches a process exit code to an installer failure. The
// command layer decides the code; main only asks ExitCode. Matching on
// message text (the previous approach) broke whenever a sentence was
// reworded, which is exactly how exit 4 turned into exit 2.
type ExitStatus struct {
	Code int
	Err  error
}

func (e *ExitStatus) Error() string { return e.Err.Error() }
func (e *ExitStatus) Unwrap() error { return e.Err }

// ExitCode maps an installer error to the documented exit code:
// 2 for usage, 3 for a node that is already installed, 4 for none.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var status *ExitStatus
	if errors.As(err, &status) {
		return status.Code
	}
	var usage *UsageError
	if errors.As(err, &usage) {
		return ExitUsage
	}
	return ExitError
}

func notInstalled(format string, args ...any) error {
	return &ExitStatus{Code: ExitNotInstalled, Err: fmt.Errorf("Not installed: "+format, args...)}
}

func alreadyInstalled(format string, args ...any) error {
	return &ExitStatus{Code: ExitAlready, Err: fmt.Errorf("Already installed: "+format, args...)}
}
