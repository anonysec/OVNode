// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"ovnode/internal/fsx"
	"strings"
	"syscall"
)

// The client-certificate lifecycle: issuing, revoking and reporting.
//
// The Go CA issues instead of the easyrsa fork. It signs in milliseconds
// instead of up to 120 seconds, it never blocks a request goroutine, and it
// writes the very same tree the OpenVPN server and the profile builder read
// (issued/<cn>.crt, private/<cn>.key). The CRL it regenerates lands in the
// file server.conf points crl-verify at, so revocation keeps working.
//
// The easyrsa wrapper stays for the install-time bootstrap (build-ca,
// build-server-full, gen-crl) where the tree does not exist yet.

// IssuedCertPath returns the path of an issued client certificate.
func IssuedCertPath(cn string) string {
	return filepath.Join(PKIDir(), "issued", cn+".crt")
}

// ClientKeyPath returns the path of a client private key.
func ClientKeyPath(cn string) string {
	return filepath.Join(PKIDir(), "private", cn+".key")
}

// InlineBundlePath returns the easy-rsa style inline bundle of a client.
func InlineBundlePath(cn string) string {
	return filepath.Join(PKIDir(), "inline", "private", cn+".inline")
}

// lockPKI takes the PKI write lock.
//
// Issuing and revoking both move the serial and rewrite the index, so they
// must not interleave: two concurrent issuances would hand out the same
// serial.
func lockPKI() (func(), error) {
	path := filepath.Join(PKIDir(), ".issue.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return func() {}, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// IssueClientCertToTree issues a client certificate and installs it in the
// PKI tree: the issued certificate, the private key and the inline bundle.
//
// The certificate lands in issued/<cn>.crt and the key in private/<cn>.key —
// the paths the easy-rsa tooling and the profile builder use — so the tree
// stays readable by both implementations.
func IssueClientCertToTree(cn string) (string, string, error) {
	if _, err := fsx.SafeCN(cn); err != nil {
		return "", "", err
	}
	unlock, err := lockPKI()
	if err != nil {
		return "", "", err
	}
	defer unlock()

	certPEM, keyPEM, err := IssueClientCert(cn)
	if err != nil {
		return "", "", err
	}
	caPEM, err := os.ReadFile(CACert())
	if err != nil {
		return "", "", err
	}
	for _, d := range []string{
		filepath.Join(PKIDir(), "issued"),
		filepath.Join(PKIDir(), "private"),
		filepath.Join(PKIDir(), "inline", "private"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", "", err
		}
	}
	if err := os.WriteFile(IssuedCertPath(cn), []byte(certPEM), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(ClientKeyPath(cn), []byte(keyPEM), 0o600); err != nil {
		return "", "", err
	}
	bundle := "# OVNode inline bundle\n# commonName: " + cn + "\n\n" +
		"<cert>\n" + strings.TrimSpace(certPEM) + "\n</cert>\n\n" +
		"<key>\n" + strings.TrimSpace(keyPEM) + "\n</key>\n\n" +
		"<ca>\n" + strings.TrimSpace(string(caPEM)) + "\n</ca>\n"
	if err := os.WriteFile(InlineBundlePath(cn), []byte(bundle), 0o600); err != nil {
		return "", "", err
	}
	return certPEM, keyPEM, nil
}

// RevokeCertByCN marks the certificate of cn revoked in the CA index and
// regenerates the CRL, so OpenVPN's crl-verify refuses it.
//
// A certificate the panel pushed was never issued by this CA: revoking it
// here would list a serial the local index never knew, so the caller only
// revokes what it issued.
//
// The revoke is idempotent: a retried delete must not fail because the
// index already says "R".
func RevokeCertByCN(cn string) error {
	if _, err := fsx.SafeCN(cn); err != nil {
		return err
	}
	unlock, err := lockPKI()
	if err != nil {
		return err
	}
	defer unlock()
	serial, valid, err := serialForCN(cn)
	if err != nil {
		return err
	}
	if !valid {
		// Already revoked: make sure the CRL covers it.
		return GenerateCRL()
	}
	// The CRL must be regenerable before the index says "R": a mark
	// without a CRL leaves the certificate valid.
	if err := GenerateCRL(); err != nil {
		return err
	}
	return RevokeCert(serial)
}

// serialForCN returns the serial of the certificate of cn and whether it is
// still valid.
func serialForCN(cn string) (string, bool, error) {
	data, err := os.ReadFile(filepath.Join(PKIDir(), "index.txt"))
	if err != nil {
		return "", false, err
	}
	for _, ln := range strings.Split(string(data), "\n") {
		fields := strings.Split(ln, "\t")
		if len(fields) < 6 {
			continue
		}
		if fields[5] != "/CN="+cn {
			continue
		}
		return fields[3], fields[0] == "V", nil
	}
	return "", false, fmt.Errorf("no valid certificate for cn %q", cn)
}

// RemoveClientMaterial deletes the certificate, key and inline bundle of a
// client from the PKI tree.
//
// The CRL already refuses the certificate; this only clears the dead
// material so nobody can read a revoked key off the disk.
func RemoveClientMaterial(cn string) {
	if _, err := fsx.SafeCN(cn); err != nil {
		return
	}
	for _, p := range []string{IssuedCertPath(cn), ClientKeyPath(cn), InlineBundlePath(cn)} {
		_ = os.Remove(p)
	}
}

// Healthy reports whether the local PKI is usable.
//
// The CA certificate, the CA key and the server certificate must all be
// there: without the CA key the node can neither issue nor revoke, and
// without the server certificate the server cannot start.
func Healthy() bool {
	for _, p := range []string{
		CACert(),
		filepath.Join(PKIDir(), "private", "ca.key"),
		ServerCert(),
	} {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

// RenewServerCert renews the server certificate.
//
// The Go CA signs it directly: the easyrsa fork takes up to 120 seconds and
// the renewed certificate must land in the tree server.conf reads. The
// easyrsa path stays as the fallback for a tree the Go CA cannot load.
func RenewServerCert() error {
	if err := RenewServerCertificateNative(); err == nil {
		return nil
	}
	if RenewServerCertificate() {
		return nil
	}
	return fmt.Errorf("server certificate renewal failed")
}

// CertExpiry returns the notAfter date of a PEM certificate as an ISO date
// ("2027-08-12"), or "" when the file is missing or unreadable.
//
// The Python agent shelled out to `openssl x509 -enddate`; crypto/x509 reads
// the same field without the fork.
func CertExpiry(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return ""
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return ""
		}
		return cert.NotAfter.UTC().Format("2006-01-02")
	}
}
