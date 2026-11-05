package updater

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTriggerUpdateValidatesVersion(t *testing.T) {
	if err := TriggerUpdate(t.TempDir(), "1.2"); err == nil {
		t.Fatal("expected invalid version")
	}
}

func TestTriggerUpdateRequiresRootOwnedInstaller(t *testing.T) {
	// The root-ownership check only guards a real upgrade: it runs as root, so
	// a non-root process cannot chown an installer to nobody, and the refusal
	// path is not exercised. Skip the check on non-root runners.
	if os.Getuid() != 0 {
		t.Skip("skipping: root-ownership refusal needs a root process")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "install.sh")
	os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755)
	// chown to nobody (65534)
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatalf("chown to nobody: %v", err)
	}
	if err := TriggerUpdate(dir, ""); err == nil {
		t.Fatal("expected refusal for non-root owner")
	}
}
