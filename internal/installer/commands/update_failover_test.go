// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateFailsOverWhenUnitWriteFailsAfterSwap(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TestFakeRunner", "1")
	app := filepath.Join(root, "app")
	previous := app + ".previous"
	data := filepath.Join(root, "data")
	ovpn := filepath.Join(root, "openvpn")
	for _, dir := range []string{app, previous, data, ovpn} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(app, "VERSION"), []byte("2.0.21"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := []byte("#!/bin/sh\nexit 0\n")
	for _, path := range []string{filepath.Join(previous, "ovnode-server"), filepath.Join(app, "ovnode-server")} {
		if err := os.WriteFile(path, bin, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	blocker := filepath.Join(root, "systemd-blocker")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SystemdDir", filepath.Join(blocker, "system"))

	c := &Config{
		AppDir: app, DataBase: data, OpenVPNRoot: ovpn, BackupDir: filepath.Join(root, "backups"),
		Local: true, Version: "1.0", NodeName: "test",
		Service: "test.service", NatService: "test-nat.service", Port: "2083",
	}
	if err := Update(c, DefaultRunner()); err == nil {
		t.Fatal("update with a failing unit write must report an error")
	}
	got, err := os.ReadFile(filepath.Join(app, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "2.0.21" {
		t.Fatalf("AppDir holds version %q after failed unit write, want 2.0.21", got)
	}
	if snaps, _ := filepath.Glob(filepath.Join(root, "backups", "node-code-*.tar.gz")); len(snaps) == 0 {
		t.Fatal("update did not write a code snapshot for rollback")
	}
	if _, err := os.Stat(previous); !os.IsNotExist(err) {
		t.Fatalf("previous tree survived a failed update: %v", err)
	}
}
