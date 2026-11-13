// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"os"
	"path/filepath"
	"testing"
)

// The sessions directory is writable by the dropped-UID runtime user, so a
// marker read must not follow a planted symlink.
func TestReadMarkerRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("common_name=u1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "u1.10.8.0.2")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadMarker(link); ok {
		t.Fatal("ReadMarker followed a symlink")
	}
}
