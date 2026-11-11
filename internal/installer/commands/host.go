package commands

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// hasSystemd mirrors lib.sh has_systemd.
func hasSystemd() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// systemctlBounded mirrors lib.sh systemctl_bounded.
func systemctlBounded(r Runner, verb, unit string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found")
	}
	// Bounded through the same timeout window as bash (OVN_STOP_TIMEOUT
	// defaults to 20s); implemented by exec.Cmd context in the caller.
	return r.Run("systemctl", verb, unit)
}

// systemctlDirect runs systemctl with no timeout handling (best effort).
func systemctlDirect(r Runner, args ...string) error {
	return r.Run("systemctl", args...)
}

// isTTY reports whether stdin and stderr are both terminals.
func isTTY() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	if stat.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	stat2, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return stat2.Mode()&os.ModeCharDevice != 0
}

// checkRoot mirrors lib.sh check_root.
func checkRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	return nil
}

// primaryIP mirrors lib.sh primary_ip.
func primaryIP(r Runner) string {
	out, err := r.Output("hostname", "-I")
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}

// publicIP mirrors lib.sh public_ip (best effort).
func publicIP(r Runner) string {
	if v := strings.TrimSpace(envOr("OVNODE_PUBLIC_IP", "")); v != "" {
		return v
	}
	// hostname -I is the only source lib.sh uses before any curl-based
	// lookup; keep the same behaviour here.
	return primaryIP(r)
}

// killProcess mirrors kill -0 checks used by operation_begin.
func killProcess(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil
}

// dirOf mirrors bash dirname.
// envOr reads an env var with fallback.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
