// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package updater

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestUpdateStatus(t *testing.T) {
	dir := t.TempDir()

	// (a) no file -> "idle"
	if got := UpdateStatus(dir); got != "idle" {
		t.Fatalf("no file: got %q, want idle", got)
	}

	// (b) "running" and no lock held -> "interrupted"
	if err := os.WriteFile(filepath.Join(dir, statusName), []byte("running\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// lock file exists but nobody holds the flock
	if f, err := os.OpenFile(filepath.Join(dir, lockName), os.O_CREATE|os.O_RDWR, 0o600); err == nil {
		f.Close()
	} else {
		t.Fatal(err)
	}
	if got := UpdateStatus(dir); got != "interrupted" {
		t.Fatalf("running no lock: got %q, want interrupted", got)
	}

	// (c) "running" and lock held by test -> "running"
	lf, err := os.OpenFile(filepath.Join(dir, lockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	if got := UpdateStatus(dir); got != "running" {
		t.Fatalf("running locked: got %q, want running", got)
	}

	// (d) "completed" -> "completed"
	if err := os.WriteFile(filepath.Join(dir, statusName), []byte("completed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := UpdateStatus(dir); got != "completed" {
		t.Fatalf("completed: got %q, want completed", got)
	}
}
