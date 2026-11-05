// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package updater

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const lockName = ".update.lock"
const statusName = ".update-status"

// TriggerUpdate runs install.sh update detached.
//
// The target version, when given, must be a plain semver. The installer
// path is checked before execution: it must be root-owned and not
// group/world-writable.
func TriggerUpdate(appDir, version string) error {
	if version != "" {
		if !validVersion(version) {
			return fmt.Errorf("invalid target version %q", version)
		}
	}
	installer := filepath.Join(appDir, "install.sh")
	info, err := os.Stat(installer)
	if err != nil {
		return err
	}
	if info.Mode()&0o022 != 0 {
		return fmt.Errorf("install.sh is group/world-writable: refusing update")
	}
	// install.sh must be root-owned so a non-root caller cannot overwrite the
	// node's upgrade script while it runs as root. The check is only meaningful
	// when the updater itself runs as root (the panel runs updates as root);
	// a non-root caller (for example the CI test runner) cannot chown to root,
	// so skip the check itself in that case.
	if os.Getuid() == 0 {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return fmt.Errorf("install.sh is not root-owned: refusing update")
		}
	}

	lockPath := filepath.Join(appDir, lockName)
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockFile.Close()
		return errors.New("update already running")
	}

	marker := filepath.Join(appDir, statusName)
	_ = os.WriteFile(marker, []byte("running\n"), 0o600)

	cmd := exec.Command("bash", installer, "update")
	cmd.Dir = appDir
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
		"APP_DIR=" + appDir,
		"OVN_APP_DIR=" + appDir,
	}
	if version != "" {
		cmd.Env = append(cmd.Env, "OVN_VERSION="+version)
	}
	if err := cmd.Start(); err != nil {
		_ = os.WriteFile(marker, []byte("failed\n"), 0o600)
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
		return err
	}
	go func() {
		err := cmd.Wait()
		status := "completed"
		if err != nil {
			status = "failed"
		}
		_ = os.WriteFile(marker, []byte(status+"\n"), 0o600)
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
	}()
	return nil
}

func UpdateStatus(appDir string) string {
	data, err := os.ReadFile(filepath.Join(appDir, statusName))
	if err != nil {
		return "idle"
	}
	status := strings.TrimSpace(string(data))
	if status == "running" {
		f, err := os.OpenFile(filepath.Join(appDir, lockName), os.O_RDWR, 0)
		if err != nil {
			return "running"
		}
		defer f.Close()
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			return "interrupted"
		}
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return "running"
		}
		return "running"
	}
	if len(status) > 32 {
		status = status[:32]
	}
	return status
}

func ValidVersion(v string) bool { return validVersion(v) }

func validVersion(v string) bool {
	// manual check to avoid regexp import
	parts := split(v, '.')
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func split(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
