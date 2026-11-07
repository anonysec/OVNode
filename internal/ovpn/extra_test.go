// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"path/filepath"
	"testing"

	"ovnode/internal/pki"
	"ovnode/internal/store"
)

func TestDeleteUserRemovesAllCopies(t *testing.T) {
	requireProviderPKI(t)
	providerTree(t)
	if err := InitPKI(); err != nil {
		t.Fatal(err)
	}
	cn := "testuser"
	if err := CreateUser(cn, "Test user", 3, nil); err != nil {
		t.Fatal(err)
	}
	dir, _ := store.UserDir(pki.UsersDir(), cn)
	for name, path := range map[string]string{"cert.pem": pki.IssuedCertPath(cn), "key.pem": pki.ClientKeyPath(cn), "ca.pem": pki.CACert()} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	found, err := DeleteUser(cn)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected found")
	}
	for _, p := range []string{
		pki.IssuedCertPath(cn),
		pki.ClientKeyPath(cn),
		pki.InlineBundlePath(cn),
		filepath.Join(dir, "cert.pem"),
		filepath.Join(dir, "key.pem"),
		filepath.Join(dir, "client.ovpn"),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("file still exists: %s", p)
		}
	}
	if store.UserExists(pki.UsersDir(), cn) {
		t.Fatal("user dir still exists")
	}
}
