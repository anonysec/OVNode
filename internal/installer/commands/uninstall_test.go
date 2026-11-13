// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package commands

import (
	"os"
	"path/filepath"
	"testing"
)

// A purge deletes the CA and every issued certificate, so a backup that
// cannot copy a member must fail instead of returning a partial archive.
func TestBackupDirFailsOnUnreadableMember(t *testing.T) {
	src := t.TempDir()
	if err := os.Symlink("missing", filepath.Join(src, "broken")); err != nil {
		t.Fatal(err)
	}
	if err := backupDir(src, filepath.Join(t.TempDir(), "dst")); err == nil {
		t.Fatal("backupDir succeeded despite an unreadable member")
	}
}
