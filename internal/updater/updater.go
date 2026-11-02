// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package updater

import (
	"os"
	"os/exec"
	"path/filepath"
)

// TriggerUpdate runs install.sh update detached.
func TriggerUpdate(appDir string) error {
	installer := filepath.Join(appDir, "install.sh")
	if _, err := os.Stat(installer); err != nil {
		return err
	}
	cmd := exec.Command("bash", installer, "update")
	cmd.Dir = appDir
	// detached: reap the child so it cannot become a zombie.
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
