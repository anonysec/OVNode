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
	"time"
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

	existingKey, err := os.ReadFile(ClientKeyPath(cn))
	if err != nil && !os.IsNotExist(err) {
		return "", "", err
	}
	if os.IsNotExist(err) {
		if _, err := os.Lstat(IssuedCertPath(cn)); err == nil {
			return "", "", fmt.Errorf("existing certificate for %q has no private key", cn)
		} else if !os.IsNotExist(err) {
			return "", "", err
		}
	}
	certPEM, keyPEM, err := issueClientCert(cn, existingKey)
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
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", "", err
		}
	}
	if err := fsx.WriteFileAtomic(IssuedCertPath(cn), []byte(certPEM), 0o600); err != nil {
		return "", "", err
	}
	if existingKey == nil {
		if err := fsx.WriteFileAtomic(ClientKeyPath(cn), []byte(keyPEM), 0o600); err != nil {
			return "", "", err
		}
	}
	bundle := "# OVNode inline bundle\n# commonName: " + cn + "\n\n" +
		"<cert>\n" + strings.TrimSpace(certPEM) + "\n</cert>\n\n" +
		"<key>\n" + strings.TrimSpace(keyPEM) + "\n</key>\n\n" +
		"<ca>\n" + strings.TrimSpace(string(caPEM)) + "\n</ca>\n"
	if err := fsx.WriteFileAtomic(InlineBundlePath(cn), []byte(bundle), 0o600); err != nil {
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
	return revokeCertByCN(cn)
}

func revokeCertByCN(cn string) error {
	ca, _, err := loadCASigner()
	if err != nil {
		return err
	}
	rows, err := readIndex()
	if err != nil {
		return err
	}
	serials := map[string]bool{}
	for _, row := range rows {
		if indexHasCN(row, cn) {
			n, _ := hexNumber(row[3])
			serials[n.Text(16)] = true
		}
	}
	for _, path := range []string{IssuedCertPath(cn), filepath.Join(UsersDir(), cn, "cert.pem"), filepath.Join(UsersDir(), cn, "client.ovpn")} {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if filepath.Ext(path) == ".ovpn" {
			_, body, ok := strings.Cut(string(data), "<cert>")
			if !ok {
				return fmt.Errorf("cached profile has no certificate for %q", cn)
			}
			body, _, ok = strings.Cut(body, "</cert>")
			if !ok {
				return fmt.Errorf("cached profile has an incomplete certificate for %q", cn)
			}
			data = []byte(body)
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("invalid certificate at %s", path)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		if cert.Subject.CommonName != cn {
			return fmt.Errorf("certificate at %s does not belong to %q", path, cn)
		}
		if err := cert.CheckSignatureFrom(ca); err != nil {
			return fmt.Errorf("cannot revoke foreign certificate at %s locally: %w", path, err)
		}
		if !serials[cert.SerialNumber.Text(16)] {
			return fmt.Errorf("certificate at %s is absent from the local index", path)
		}
	}
	if len(serials) == 0 {
		return fmt.Errorf("no certificate index records for %q", cn)
	}
	changed := false
	now := time.Now().UTC().Format("060102150405Z")
	for _, row := range rows {
		if indexHasCN(row, cn) && row[0] != "R" {
			row[0], row[2] = "R", now
			changed = true
		}
	}
	if changed {
		if err := writeIndex(rows); err != nil {
			return err
		}
	}
	if err := GenerateCRL(); err != nil {
		return err
	}
	list, err := readCRL()
	if err != nil {
		return err
	}
	if err := list.CheckSignatureFrom(ca); err != nil {
		return err
	}
	for _, entry := range list.RevokedCertificateEntries {
		delete(serials, entry.SerialNumber.Text(16))
	}
	if len(serials) != 0 {
		return fmt.Errorf("persisted CRL does not cover every certificate for %q", cn)
	}
	return nil
}

func indexHasCN(row []string, cn string) bool {
	for _, field := range strings.Split(row[5], "/") {
		if field == "CN="+cn {
			return true
		}
	}
	return false
}

// RefreshCRL regenerates the CRL under the PKI lock. It is safe to call
// from a long-running service's periodic refresh.
func RefreshCRL() bool {
	unlock, err := lockPKI()
	if err != nil {
		return false
	}
	defer unlock()
	return EnsureCRL()
}

// RegenerateCRL regenerates the CRL immediately, ignoring its expiry.
func RegenerateCRL() bool {
	unlock, err := lockPKI()
	if err != nil {
		return false
	}
	defer unlock()
	return GenerateCRL() == nil
}

// WithPKILock runs fn while holding the PKI write lock.
func WithPKILock(fn func() error) error {
	unlock, err := lockPKI()
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

// Hold the PKI lock through verified revocation and material removal.
func RemoveClientMaterial(cn string) error {
	if _, err := fsx.SafeCN(cn); err != nil {
		return err
	}
	unlock, err := lockPKI()
	if err != nil {
		return err
	}
	defer unlock()
	if err := revokeCertByCN(cn); err != nil {
		return err
	}
	for _, p := range []string{IssuedCertPath(cn), ClientKeyPath(cn), InlineBundlePath(cn)} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
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
	unlock, err := lockPKI()
	if err != nil {
		return err
	}
	defer unlock()
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
