// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"testing"

	"ovnode/internal/pki"
	"ovnode/internal/store"
)

// TestCreateUserWithCredentialsPreservesLimit: a credential re-push with a
// nil limit must not clobber an existing limit (or unlimited=0).
func TestCreateUserWithCredentialsPreservesLimit(t *testing.T) {
	providerTree(t)
	if err := InitPKI(); err != nil {
		t.Fatal(err)
	}
	if err := CreateUser("alice", "Alice", 3, nil); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(pki.IssuedCertPath("alice"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(pki.ClientKeyPath("alice"))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(pki.CACert())
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateUserWithCredentials("alice", string(certPEM), string(keyPEM), string(caPEM), nil, nil); err != nil {
		t.Fatal(err)
	}
	st, err := store.ReadUserState(pki.UsersDir(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !st.LimitSet || st.Limit != 3 {
		t.Fatalf("limit after nil re-push = %+v, want 3", st)
	}
}
