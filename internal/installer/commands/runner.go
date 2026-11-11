package commands

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	ExitOK           = 0
	ExitError        = 1
	ExitUsage        = 2
	ExitAlready      = 3
	ExitNotInstalled = 4
)

// Runner is the process boundary. The default runner executes real
// programs; tests replace it with a recording stub.
type Runner interface {
	Run(name string, args ...string) error
	Output(name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (execRunner) Output(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

var fakeRunner *recordingRunner
var fakeOnce sync.Once

func DefaultRunner() Runner {
	if v := os.Getenv("OVNODE_FAKE_RUNNER"); v == "1" {
		fakeOnce.Do(func() { fakeRunner = &recordingRunner{} })
		return fakeRunner
	}
	return execRunner{}
}

type recordingRunner struct {
	mu   sync.Mutex
	Run2 []string
}

func (r *recordingRunner) Run(name string, args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Run2 = append(r.Run2, name+" "+strings.Join(args, " "))
	return nil
}

func (r *recordingRunner) Output(name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Run2 = append(r.Run2, name+" "+strings.Join(args, " "))
	return []byte{}, nil
}

func (r *recordingRunner) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.Run2))
	copy(out, r.Run2)
	return out
}

// isFake reports whether the current process was asked to record calls.
func isFake() bool { return os.Getenv("OVNODE_FAKE_RUNNER") == "1" }

// hold writes the fake-runner calls to a file named by OVNODE_FAKE_LOG.
// The fake binary is a separate process, so the recorder cannot be read
// back in the caller.
func hold(r Runner) {
	rr, ok := r.(*recordingRunner)
	if !ok {
		return
	}
	path := os.Getenv("OVNODE_FAKE_LOG")
	if path == "" {
		return
	}
	var b strings.Builder
	for _, c := range rr.Calls() {
		b.WriteString(c)
		b.WriteByte('\n')
	}
	_ = os.WriteFile(path, []byte(b.String()), 0o644)
}

var _ = time.Now
