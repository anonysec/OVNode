// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pairing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPairingLease(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	os.MkdirAll(filepath.Join(dir, "ovnode", "state"), 0o755)
	if err := Enforce("panel-a"); err != nil {
		t.Fatal(err)
	}
	// foreign panel refused while lease holds
	if err := Enforce("panel-b"); err == nil {
		t.Fatal("expected refusal")
	}
	// same panel refreshes
	if err := Enforce("panel-a"); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, "ovnode", "state", "pairing.json"))
	if _, err := os.Stat(filepath.Join(dir, "ovnode", "state", "pairing.json")); !os.IsNotExist(err) {
		t.Fatal("expected file gone after disconnect")
	}
}
