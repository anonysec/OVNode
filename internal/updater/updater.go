// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package updater

import (
	"os"
	"os/exec"
	"path/filepath"
)

// IsDocker reports whether running in a container.
func IsDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	return false
}

// TriggerUpdate runs install.sh update detached. Returns error if refused.
func TriggerUpdate(appDir string) error {
	if IsDocker() {
		return os.ErrPermission
	}
	installer := filepath.Join(appDir, "install.sh")
	if _, err := os.Stat(installer); err != nil {
		return err
	}
	cmd := exec.Command("bash", installer, "update")
	cmd.Dir = appDir
	// detached
	cmd.Start()
	return nil
}
