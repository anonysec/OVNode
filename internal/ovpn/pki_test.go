// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovnode/internal/fsx"
	"ovnode/internal/pki"
)

func providerTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("OpenVpnRoot", filepath.Join(root, "openvpn"))
	t.Setenv("DataDir", filepath.Join(root, "data"))
	t.Setenv("UsersDir", filepath.Join(root, "data", "users"))
	t.Setenv("SessionsDir", filepath.Join(root, "data", "sessions"))
	t.Setenv("UsageDir", filepath.Join(root, "data", "usage"))
	t.Setenv("LogDir", filepath.Join(root, "logs"))
	t.Setenv("LogFile", filepath.Join(root, "logs", "events.log"))
	t.Setenv("StatusFile", filepath.Join(root, "openvpn", "server", "status.log"))
	t.Setenv("MgmtPassFile", filepath.Join(root, "openvpn", "server", "mgmt-pass"))
	if err := os.MkdirAll(filepath.Join(root, "openvpn", "server"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func requireProviderPKI(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openvpn"); err != nil {
		t.Skip("openvpn is required")
	}
	if _, err := os.Stat("/usr/share/easy-rsa/easyrsa"); err != nil {
		t.Skip("easy-rsa is required")
	}
}

func TestInitPKIFreshTree(t *testing.T) {
	requireProviderPKI(t)
	providerTree(t)
	if err := InitPKI(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{pki.CACert(), filepath.Join(pki.PKIDir(), "private", "ca.key"), pki.ServerCert(), pki.ServerKey(), pki.CRLFile(), pki.TLSKey(), pki.ClientTemplate()} {
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			t.Errorf("fresh PKI material %s: bytes=%d error=%v", path, len(data), err)
		}
	}
	conf, err := os.ReadFile(fsx.ServerConf("udp"))
	if err != nil {
		t.Fatal(err)
	}
	for directive, target := range HookTargets() {
		if strings.Count(string(conf), directive+" \""+target+"\"") != 1 {
			t.Errorf("fresh PKI does not install exactly one %s hook", directive)
		}
	}
}

func TestInitPKIPreservesExistingIdentity(t *testing.T) {
	requireProviderPKI(t)
	providerTree(t)
	if err := InitPKI(); err != nil {
		t.Fatal(err)
	}
	if err := CreateUser("alice", "Alice", 3, nil); err != nil {
		t.Fatal(err)
	}
	paths := []string{pki.CACert(), filepath.Join(pki.PKIDir(), "private", "ca.key"), pki.ServerCert(), pki.ServerKey(), pki.TLSKey(), pki.IssuedCertPath("alice"), pki.ClientKeyPath("alice"), pki.InlineBundlePath("alice")}
	before := map[string][32]byte{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = sha256.Sum256(data)
	}
	for range 2 {
		if err := InitPKI(); err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil || sha256.Sum256(data) != before[path] {
				t.Errorf("repeated initialization changed %s: %v", path, err)
			}
		}
	}
}

func TestInitPKIPartialIdentityIsNotReplaced(t *testing.T) {
	requireProviderPKI(t)
	for _, missing := range []string{"ca-cert", "ca-key", "server-cert", "server-key"} {
		t.Run(missing, func(t *testing.T) {
			providerTree(t)
			if err := InitPKI(); err != nil {
				t.Fatal(err)
			}
			if err := CreateUser("alice", "Alice", 3, nil); err != nil {
				t.Fatal(err)
			}
			paths := map[string]string{"ca-cert": pki.CACert(), "ca-key": filepath.Join(pki.PKIDir(), "private", "ca.key"), "server-cert": pki.ServerCert(), "server-key": pki.ServerKey(), "client-cert": pki.IssuedCertPath("alice"), "client-key": pki.ClientKeyPath("alice")}
			before := map[string][]byte{}
			for label, path := range paths {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				before[label] = data
			}
			if err := os.Remove(paths[missing]); err != nil {
				t.Fatal(err)
			}
			initErr := InitPKI()
			if initErr == nil {
				t.Error("partial identity was silently replaced or accepted")
			}
			for label, path := range paths {
				if label == missing {
					continue
				}
				data, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(data, before[label]) {
					t.Errorf("partial initialization changed existing %s (init error=%v, read error=%v)", label, initErr, err)
				}
			}
		})
	}
}

func TestInitPKIReportsBlockedTargets(t *testing.T) {
	requireProviderPKI(t)
	for _, target := range []string{"ccd", "vars", "tls-key", "server-conf", "template", "missing-index"} {
		t.Run(target, func(t *testing.T) {
			providerTree(t)
			if err := InitPKI(); err != nil {
				t.Fatal(err)
			}
			path := map[string]string{"ccd": filepath.Join(pki.OpenVPNRoot(), "ccd"), "vars": filepath.Join(pki.EasyRSADir(), "vars"), "tls-key": pki.TLSKey(), "server-conf": fsx.ServerConf("udp"), "template": pki.ClientTemplate(), "missing-index": filepath.Join(pki.PKIDir(), "index.txt")}[target]
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if target == "ccd" {
				if err := os.WriteFile(path, []byte("blocked directory\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if target != "missing-index" {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := InitPKI(); err == nil {
				t.Fatalf("initialization reported success with blocked %s target", target)
			}
		})
	}
}

func TestInitPKIPreservesLegacyRSACRLRenewal(t *testing.T) {
	requireProviderPKI(t)
	providerTree(t)
	if err := pki.SetupEasyRSA(); err != nil {
		t.Fatal(err)
	}
	vars := "set_var EASYRSA_ALGO rsa\nset_var EASYRSA_KEY_SIZE 2048\nset_var EASYRSA_BATCH 1\nset_var EASYRSA_CA_EXPIRE 3650\nset_var EASYRSA_CERT_EXPIRE 1825\nset_var EASYRSA_CRL_DAYS 365\n"
	if err := os.WriteFile(filepath.Join(pki.EasyRSADir(), "vars"), []byte(vars), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InitPKI(); err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(pki.CACert())
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(pki.PKIDir(), "private", "ca.key")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(pki.CRLFile())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("real RSA fixture CRL has no PEM block")
	}
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	list.ThisUpdate, list.NextUpdate = time.Now().Add(-time.Hour), time.Now().Add(15*24*time.Hour)
	list.Number = big.NewInt(4096)
	der, err := x509.CreateRevocationList(rand.Reader, list, ca, pair.PrivateKey.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pki.CRLFile(), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InitPKI(); err != nil {
		t.Fatalf("checked initialization broke legacy RSA CRL renewal: %v", err)
	}
	after, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(keyPEM, after) {
		t.Fatalf("legacy RSA renewal changed CA key bytes: %v", err)
	}
	if days := pki.CRLDaysRemaining(); days <= pki.CRLRenewThresholdDays {
		t.Fatalf("legacy RSA CRL was not renewed: remaining days=%d", days)
	}
}
