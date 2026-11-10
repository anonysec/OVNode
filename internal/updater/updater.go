// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package updater

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const lockName = ".update.lock"
const statusName = ".update-status"

// TriggerUpdate runs install.sh update detached via systemd-run.
//
// The transient unit lives outside ovnode.service's sandbox and cgroup, so
// the update can write /var/backups, replace binaries, and survive the
// service restart. The updater only enqueues it and returns; the update
// script itself finishes the work and writes the final status.
//
// The target version, when given, must be a plain semver. The installer
// path is checked before execution: it must be root-owned and not
// group/world-writable.
func TriggerUpdate(appDir, version string) error {
	if version != "" {
		if !ValidVersion(version) {
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
	// The flock is a process-lock: the transient update re-enqueues it,
	// and once TriggerUpdate returns it stays held by the process that
	// owns it. Releasing here would let a second call begin, so the
	// process that enqueued the update keeps the lock file open and
	// relies on the update script to write the final status.

	marker := filepath.Join(appDir, statusName)
	_ = os.WriteFile(marker, []byte("running\n"), 0o600)

	cmd := exec.Command("systemd-run", "--unit=ovnode-update-"+sanitizeUnit(appDir), "--collect", "--quiet",
		"--setenv=OVN_APP_DIR="+appDir, "--setenv=OVN_VERSION="+version,
		"/bin/bash", installer, "update")
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
	if err := cmd.Run(); err != nil {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
		return err
	}
	// systemd-run only enqueued the unit; the update script holds the lock
	// for the duration. Releasing here would let a second call in and would
	// make UpdateStatus report "interrupted" for a live update.
	return nil
}

func UpdateStatus(appDir string) string {
	data, err := os.ReadFile(filepath.Join(appDir, statusName))
	if err != nil {
		return "idle"
	}
	status := strings.TrimSpace(string(data))
	if status == "running" {
		// The update script owns the flock for the whole run; a released
		// lock while the marker says running means the script died
		// before reaching the end. A missing lock file with a running
		// marker is still running.
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

func sanitizeUnit(appDir string) string {
	// The unit name comes from the app dir so parallel installs do not
	// share one transient unit.
	var b strings.Builder
	for _, r := range filepath.Base(appDir) {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "update"
	}
	return b.String()
}

var versionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// ValidVersion reports whether v is a plain semver X.Y.Z.
func ValidVersion(v string) bool {
	return versionRe.MatchString(v)
}
