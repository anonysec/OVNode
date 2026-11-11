// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestGenerateCRLRejectsCorruptRevocationData(t *testing.T) {
	for _, failure := range []string{"missing-index", "index-directory", "malformed-row", "bad-serial", "bad-expiry", "bad-revocation-time", "bad-number", "number-directory", "crl-directory", "corrupt-crl"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("OpenVpnRoot", root)
			t.Setenv("DataDir", root+"/ovnode-data")
			writeTestCA(t, root)
			if err := GenerateCRL(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(CRLFile())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(PKIDir(), "index.txt")
			body := "broken\n"
			switch failure {
			case "bad-serial":
				body = "R\t301106000000Z\t261106000000Z\tinvalid\tunknown\t/CN=alice\n"
			case "bad-expiry":
				body = "R\tinvalid\t261106000000Z\t1000\tunknown\t/CN=alice\n"
			case "bad-revocation-time":
				body = "R\t301106000000Z\tinvalid\t1000\tunknown\t/CN=alice\n"
			case "bad-number", "number-directory":
				path = filepath.Join(PKIDir(), "crlnumber")
			case "crl-directory", "corrupt-crl":
				path = CRLFile()
			}
			if strings.HasSuffix(failure, "directory") || failure == "missing-index" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if failure != "missing-index" {
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				}
			} else if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := GenerateCRL(); err == nil {
				t.Errorf("CRL generation ignored %s and reported success", failure)
			}
			if path != CRLFile() {
				after, err := os.ReadFile(CRLFile())
				if err != nil || !bytes.Equal(before, after) {
					t.Errorf("failed generation replaced the previous CRL: %v", err)
				}
			}
		})
	}
}

func TestGenerateCRLDoesNotLosePreviousRevocations(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OpenVpnRoot", root)
	t.Setenv("DataDir", root+"/ovnode-data")
	writeTestCA(t, root)
	certPEM, _, err := IssueClientCertToTree("alice")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pemBlock([]byte(certPEM)).Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := RevokeCertByCN("alice"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(PKIDir(), "index.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_ = GenerateCRL()
	data, err := os.ReadFile(CRLFile())
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
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return
		}
	}
	t.Fatal("regeneration silently removed a previously durable revocation")
}

func TestRevokeCertRejectsUnknownSerial(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OpenVpnRoot", root)
	writeTestCA(t, root)
	if err := RevokeCert("BEEF"); err == nil {
		t.Fatal("unknown serial was acknowledged as revoked")
	}
}

func TestIssueClientCertPreservesUnterminatedIndex(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OpenVpnRoot", root)
	writeTestCA(t, root)
	if _, _, err := IssueClientCertToTree("alice"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(PKIDir(), "index.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.TrimSuffix(data, []byte("\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := IssueClientCertToTree("bob"); err != nil {
		t.Fatal(err)
	}
	rows, err := readIndex()
	if err != nil || len(rows) != 2 {
		t.Fatalf("issuance corrupted an unterminated existing index: rows=%d error=%v", len(rows), err)
	}
}

func TestRevokeExpiredAndReissuedCertificates(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OpenVpnRoot", root)
	t.Setenv("DataDir", root+"/ovnode-data")
	writeTestCA(t, root)
	certPEM, _, err := IssueClientCertToTree("alice")
	if err != nil {
		t.Fatal(err)
	}
	expired, err := x509.ParseCertificate(pemBlock([]byte(certPEM)).Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ca, caKey, err := loadCA()
	if err != nil {
		t.Fatal(err)
	}
	expired.NotBefore = time.Now().Add(-48 * time.Hour)
	expired.NotAfter = time.Now().Add(-24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, expired, ca, expired.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(IssuedCertPath("alice"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	rows, err := readIndex()
	if err != nil {
		t.Fatal(err)
	}
	rows[0][0], rows[0][1], rows[0][5] = "E", expired.NotAfter.UTC().Format("060102150405Z"), "/C=GB/O=Operator/CN=alice"
	if err := writeIndex(rows); err != nil {
		t.Fatal(err)
	}
	if err := RevokeCertByCN("alice"); err != nil {
		t.Fatal(err)
	}
	certPEM, _, err = IssueClientCertToTree("alice")
	if err != nil {
		t.Fatal(err)
	}
	current, err := x509.ParseCertificate(pemBlock([]byte(certPEM)).Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := RevokeCertByCN("alice"); err != nil {
		t.Fatal(err)
	}
	list, err := readCRL()
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range []*x509.Certificate{expired, current} {
		found := false
		for _, entry := range list.RevokedCertificateEntries {
			found = found || entry.SerialNumber.Cmp(cert.SerialNumber) == 0
		}
		if !found {
			t.Errorf("expired/reissued serial %X was not durably revoked", cert.SerialNumber)
		}
	}
}

func TestRevokeIndexWriteErrorProcess(t *testing.T) {
	if os.Getenv("TestPROVIDER_INDEX_WRITE") == "" {
		return
	}
	if err := RevokeCert("1000"); !os.IsPermission(err) {
		t.Fatalf("checked index write did not return its actual filesystem error: %v", err)
	}
}

func TestRevokePropagatesIndexWriteError(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required to run an isolated unprivileged writer")
	}
	root, err := os.MkdirTemp("", "ovnode-index-write-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OpenVpnRoot", root)
	writeTestCA(t, root)
	if _, _, err := IssueClientCertToTree("alice"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(PKIDir(), "index.txt"))
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(root, "index-write-test")
	if err := os.WriteFile(probe, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(root, "child-tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(tmp, 65533, 65533); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, probe, "-test.run=^TestRevokeIndexWriteErrorProcess$")
	cmd.Env = append(os.Environ(), "TestPROVIDER_INDEX_WRITE=1", "TMPDIR="+tmp)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 65533}}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unprivileged index write probe: %v\n%s", err, output)
	}
	after, err := os.ReadFile(filepath.Join(PKIDir(), "index.txt"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed index write changed certificate state: %v", err)
	}
}
