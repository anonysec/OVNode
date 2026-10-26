// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pki

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCRLAfterInit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	os.MkdirAll(filepath.Join(dir, "server", "pki"), 0o755)
	// init pki via easyrsa won't be available in test env; skip if no ca
	if _, err := os.Stat(CACert()); err != nil {
		t.Skip("no CA")
	}
	if err := GenerateCRL(); err != nil {
		t.Fatalf("gen crl: %v", err)
	}
	if _, err := os.Stat(CRLFile()); err != nil {
		t.Fatal("crl not created")
	}
}
