// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package commands

import (
	"os"
	"path/filepath"
	"testing"

	"ovnode/internal/installer"
)

func TestFailoverRestoresPreviousTree(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(app, "VERSION"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(previous, "VERSION"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	safety, err := installer.Bundle(previous, data, ovpn, filepath.Join(root, "backups"), "test", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	c := &Config{
		AppDir: app, DataBase: data, NodeName: "test",
		Service: "test.service", NatService: "test-nat.service", Port: "2083",
	}
	u := &updateCtx{from: "1.0", safety: safety, identity: "test"}
	if err := failover(c, u, DefaultRunner()); err == nil {
		t.Fatal("failover must report the failed update")
	}
	version, err := os.ReadFile(filepath.Join(app, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if string(version) != "old" {
		t.Fatalf("failover left version %q in AppDir, want old", version)
	}
}
