// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTestCA builds a CA in the tree the way easy-rsa does: the
// certificate in ca.crt and the key in PKCS#8 in private/ca.key.
func writeTestCA(t *testing.T, root string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "server", "pki", "private"), 0o755); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(root, "server", "pki", "ca.crt")
	if err := os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "server", "pki", "private", "ca.key"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	// The index and the serial file an easy-rsa tree carries.
	pkiDir := filepath.Join(root, "server", "pki")
	if err := os.WriteFile(filepath.Join(pkiDir, "index.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkiDir, "serial"), []byte("1000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkiDir, "crlnumber"), []byte("1000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestIssueClientCertToTree covers the client certificate lifecycle.
//
// The certificate has to land in the tree the OpenVPN server and the
// profile builder read, and the CRL has to list it after the revoke: the
// crl-verify directive is not optional.
func TestIssueClientCertToTree(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	writeTestCA(t, root)

	certPEM, keyPEM, err := IssueClientCertToTree("alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.Contains(certPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("the certificate is not a PEM block: %q", certPEM)
	}
	if !strings.Contains(keyPEM, "PRIVATE KEY") {
		t.Fatalf("the key is not a PEM block: %q", keyPEM)
	}
	// The tree the server and the profile builder read.
	for _, path := range []string{
		IssuedCertPath("alice"),
		ClientKeyPath("alice"),
		InlineBundlePath("alice"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s is missing: %v", path, err)
		}
	}
	// The index carries the certificate, or the CRL cannot list it later.
	index, err := os.ReadFile(filepath.Join(root, "server", "pki", "index.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), "/CN=alice") {
		t.Fatalf("the index carries no row for alice: %q", string(index))
	}

	if err := RevokeCertByCN("alice"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	crl, err := os.ReadFile(CRLFile())
	if err != nil {
		t.Fatalf("the CRL was not written: %v", err)
	}
	list, err := x509.ParseRevocationList(pemBlock(crl).Bytes)
	if err != nil {
		t.Fatalf("the CRL does not parse: %v", err)
	}
	if len(list.RevokedCertificates) != 1 {
		t.Fatalf("the CRL lists %d certificates, want 1", len(list.RevokedCertificates))
	}
}

// TestRevokeCertByCNIsIdempotent covers the retried delete.
//
// easy-rsa moves the certificate out of issued/ on the revoke, so a crash
// after the revoke leaves no certificate to find: the second attempt must
// not fail.
func TestRevokeCertByCNIsIdempotent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	writeTestCA(t, root)
	if _, _, err := IssueClientCertToTree("bob"); err != nil {
		t.Fatal(err)
	}
	if err := RevokeCertByCN("bob"); err != nil {
		t.Fatalf("the first revoke failed: %v", err)
	}
	if err := RevokeCertByCN("bob"); err != nil {
		t.Fatalf("the second revoke failed: %v", err)
	}
}

// TestIssueClientCertRejectsABadCN covers the path safety: a common name
// must never escape the PKI directory.
func TestIssueClientCertRejectsABadCN(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	writeTestCA(t, root)
	for _, cn := range []string{"../escape", "a/b", "", "."} {
		if _, _, err := IssueClientCertToTree(cn); err == nil {
			t.Errorf("the common name %q was accepted", cn)
		}
	}
}

// TestCertExpiryReadsTheNotAfterDate covers the certificate expiry the
// panel shows.
//
// The Python agent shelled out to openssl; crypto/x509 reads the same
// field without the fork.
func TestCertExpiryReadsTheNotAfterDate(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	writeTestCA(t, root)
	expiry := CertExpiry(CACert())
	if expiry == "" {
		t.Fatal("no expiry for a readable certificate")
	}
	if _, err := time.Parse("2006-01-02", expiry); err != nil {
		t.Fatalf("the expiry %q is not an ISO date: %v", expiry, err)
	}
	if CertExpiry(filepath.Join(root, "missing.crt")) != "" {
		t.Fatal("a missing certificate has an expiry")
	}
}

// pemBlock returns the first PEM block of a document.
func pemBlock(data []byte) *pem.Block {
	block, _ := pem.Decode(data)
	if block == nil {
		return &pem.Block{}
	}
	return block
}
