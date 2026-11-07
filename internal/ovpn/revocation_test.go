// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ovnode/internal/pki"
	"ovnode/internal/store"
)

func issuedCertificate(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(pki.IssuedCertPath(cn))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("issued certificate has no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func durableRevocation(t *testing.T, cert *x509.Certificate) bool {
	t.Helper()
	data, err := os.ReadFile(pki.CRLFile())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("CRL has no PEM block")
	}
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(pki.CACert())
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(caPEM)
	if block == nil {
		t.Fatal("CA has no PEM block")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := list.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

func TestDeleteUnindexedCertificateKeepsDisabledTombstone(t *testing.T) {
	requireProviderPKI(t)
	providerTree(t)
	if err := InitPKI(); err != nil {
		t.Fatal(err)
	}
	if err := CreateUser("alice", "Alice", 3, nil); err != nil {
		t.Fatal(err)
	}
	cert := issuedCertificate(t, "alice")
	indexPath := filepath.Join(pki.PKIDir(), "index.txt")
	index, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, row := range strings.Split(string(index), "\n") {
		if !strings.Contains(row, "\t/CN=alice") {
			rows = append(rows, row)
		}
	}
	if err := os.WriteFile(indexPath, []byte(strings.Join(rows, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	found, deleteErr := DeleteUser("alice")
	if !found || deleteErr == nil {
		t.Errorf("unindexed issued certificate deletion reported success: found=%t error=%v revoked=%t", found, deleteErr, durableRevocation(t, cert))
	}
	state, err := store.ReadUserState(pki.UsersDir(), "alice")
	if err != nil || !state.Disabled || state.Limit != 3 || store.ReadName(pki.UsersDir(), "alice") != "Alice" {
		t.Errorf("unverifiable deletion lost its disabled policy tombstone: %+v (%v)", state, err)
	}
	for _, path := range []string{pki.IssuedCertPath("alice"), pki.ClientKeyPath("alice"), pki.InlineBundlePath("alice")} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("unverifiable deletion destroyed recoverable material %s: %v", path, err)
		}
	}
	if t.Failed() {
		return
	}
	if err := os.WriteFile(indexPath, index, 0o644); err != nil {
		t.Fatal(err)
	}
	if found, err := DeleteUser("alice"); !found || err != nil {
		t.Fatalf("deletion retry after index repair: found=%t error=%v", found, err)
	}
	if !durableRevocation(t, cert) {
		t.Fatal("acknowledged deletion is absent from the signed on-disk CRL")
	}
	if found, err := DeleteUser("alice"); found || err != nil {
		t.Fatalf("duplicate successful deletion is not idempotent: found=%t error=%v", found, err)
	}
}

func TestDeleteRevocationFailureRetainsPolicyAndMaterial(t *testing.T) {
	requireProviderPKI(t)
	for _, failure := range []string{"index-directory", "crl-directory", "number-directory", "corrupt-index", "corrupt-number"} {
		t.Run(failure, func(t *testing.T) {
			providerTree(t)
			if err := InitPKI(); err != nil {
				t.Fatal(err)
			}
			if err := CreateUser("alice", "Alice", 3, nil); err != nil {
				t.Fatal(err)
			}
			cert := issuedCertificate(t, "alice")
			path := filepath.Join(pki.PKIDir(), "index.txt")
			if strings.HasPrefix(failure, "crl") {
				path = pki.CRLFile()
			} else if strings.Contains(failure, "number") {
				path = filepath.Join(pki.PKIDir(), "crlnumber")
			}
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(failure, "directory") {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				body := []byte("invalid number\n")
				if failure == "corrupt-index" {
					body = append(append([]byte{}, original...), []byte("R\t301106000000Z\tbad-time\tgarbage\tunknown\t/CN=other\n")...)
				}
				if err := os.WriteFile(path, body, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			found, deleteErr := DeleteUser("alice")
			if !found || deleteErr == nil {
				t.Errorf("revocation failure was acknowledged: found=%t error=%v", found, deleteErr)
			}
			state, err := store.ReadUserState(pki.UsersDir(), "alice")
			if err != nil || !state.Disabled || state.Limit != 3 || store.ReadName(pki.UsersDir(), "alice") != "Alice" {
				t.Errorf("failed revocation lost disabled policy: %+v (%v)", state, err)
			}
			if _, err := os.Stat(pki.ClientKeyPath("alice")); err != nil {
				t.Errorf("failed revocation removed the client key: %v", err)
			}
			if t.Failed() {
				return
			}
			if strings.HasSuffix(failure, "directory") {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, original, 0o644); err != nil {
				t.Fatal(err)
			}
			if found, err := DeleteUser("alice"); !found || err != nil {
				t.Fatalf("repaired revocation retry: found=%t error=%v", found, err)
			}
			if !durableRevocation(t, cert) {
				t.Fatal("successful retry has no durable CRL entry")
			}
		})
	}
}

func TestDeleteForeignCertificateFailsClosed(t *testing.T) {
	requireProviderPKI(t)
	var foreignCert, foreignKey, foreignCA string
	t.Run("foreign-fixture", func(t *testing.T) {
		providerTree(t)
		if err := InitPKI(); err != nil {
			t.Fatal(err)
		}
		var err error
		foreignCert, foreignKey, err = pki.IssueClientCertToTree("alice")
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(pki.CACert())
		if err != nil {
			t.Fatal(err)
		}
		foreignCA = string(data)
	})
	for _, kind := range []string{"pushed-only", "local-and-pushed", "foreign-issued-path"} {
		t.Run(kind, func(t *testing.T) {
			providerTree(t)
			if err := InitPKI(); err != nil {
				t.Fatal(err)
			}
			if kind != "pushed-only" {
				if err := CreateUser("alice", "Alice", 3, nil); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "foreign-issued-path" {
				if err := os.WriteFile(pki.IssuedCertPath("alice"), []byte(foreignCert), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := func() error {
				limit := 3
				return CreateUserWithCredentials("alice", foreignCert, foreignKey, foreignCA, &limit, nil)
			}(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(pki.CRLFile())
			if err != nil {
				t.Fatal(err)
			}
			found, deleteErr := DeleteUser("alice")
			if !found || deleteErr == nil {
				t.Errorf("foreign certificate deletion reported success: found=%t error=%v", found, deleteErr)
			}
			state, err := store.ReadUserState(pki.UsersDir(), "alice")
			if err != nil || !state.Disabled || state.Limit != 3 || !store.UserExists(pki.UsersDir(), "alice") {
				t.Errorf("foreign deletion removed the disabled tombstone: %+v (%v)", state, err)
			}
			after, err := os.ReadFile(pki.CRLFile())
			if err != nil || !bytes.Equal(before, after) {
				t.Errorf("foreign revocation changed local revocation data: %v", err)
			}
		})
	}
}
