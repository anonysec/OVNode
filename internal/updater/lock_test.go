// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package updater

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestTriggerUpdateHoldsLockAcrossGC(t *testing.T) {
	dir := t.TempDir()
	installerPath := filepath.Join(dir, "install.sh")
	if err := os.WriteFile(installerPath, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "systemd-run"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := TriggerUpdate(dir, ""); err != nil {
		t.Fatal(err)
	}
	defer func() {
		updateLockMu.Lock()
		f := updateLockFile
		updateLockFile = nil
		updateLockMu.Unlock()
		if f != nil {
			_ = f.Close()
		}
	}()
	runtime.GC()
	runtime.Gosched()
	if got := UpdateStatus(dir); got != "running" {
		t.Fatalf("status after GC = %q, want running", got)
	}
	if err := TriggerUpdate(dir, ""); err == nil {
		t.Fatal("a second update started while the first was in flight")
	}
}
