// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package installer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteUpdateStateWritesCompleteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update-state.json")
	if err := WriteUpdateState(path, "committed", "1.0", "2.0", "backup", "identity"); err != nil {
		t.Fatal(err)
	}
	state, err := ReadUpdateState(path)
	if err != nil {
		t.Fatal(err)
	}
	if state["phase"] != "committed" {
		t.Fatalf("phase = %v, want committed", state["phase"])
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o, want 600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestWriteUpdateStateReportsBadParent(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteUpdateState(filepath.Join(blocker, "state.json"), "committed", "", "", "", ""); err == nil {
		t.Fatal("writing state under a regular file must fail")
	}
}
