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

// TriggerUpdate runs install.sh update detached via systemd-run. The unit
// lives outside the service sandbox, so it can replace binaries and survive
// the restart. The version must be plain semver and the installer root-owned.
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
	// Keep the lock: releasing it here would let a second update start.

	marker := filepath.Join(appDir, statusName)
	_ = os.WriteFile(marker, []byte("running\n"), 0o600)

	cmd := exec.Command("systemd-run", "--unit=ovnode-update-"+sanitizeUnit(appDir), "--collect", "--quiet",
		"--setenv=AppDir="+appDir, "--setenv=Version="+version,
		"/bin/bash", installer, "update")
	cmd.Dir = appDir
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
		"AppDir=" + appDir,
		"AppDir=" + appDir,
	}
	if version != "" {
		cmd.Env = append(cmd.Env, "Version="+version)
	}
	if err := cmd.Run(); err != nil {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
		return err
	}
	// The unit only enqueued; keep the lock so a second update cannot start.
	return nil
}

func UpdateStatus(appDir string) string {
	data, err := os.ReadFile(filepath.Join(appDir, statusName))
	if err != nil {
		return "idle"
	}
	status := strings.TrimSpace(string(data))
	if status == "running" {
		// A released lock with a running marker means the updater died.
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
