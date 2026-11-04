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
	dir := t.TempDir()
	path := filepath.Join(dir, "install.sh")
	os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755)
	// chown to nobody (65534) if possible
	_ = os.Chown(path, 65534, 65534)
	if err := TriggerUpdate(dir, ""); err == nil {
		t.Fatal("expected refusal for non-root owner")
	}
}
