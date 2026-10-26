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
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// loadCA loads the CA cert and private key (PKCS#8 per V3).
func loadCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(CACert())
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("no CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(PKIDir(), "private", "ca.key"))
	if err != nil {
		return nil, nil, err
	}
	kblock, _ := pem.Decode(keyPEM)
	if kblock == nil {
		return nil, nil, fmt.Errorf("no CA key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(kblock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA key is not ECDSA")
	}
	if !ecKey.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, fmt.Errorf("CA key does not match cert")
	}
	return cert, ecKey, nil
}

// nextSerial reads serial file (hex) and increments it.
func nextSerial() (*big.Int, error) {
	data, err := os.ReadFile(filepath.Join(PKIDir(), "serial"))
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(data))
	n := new(big.Int)
	if _, ok := n.SetString(s, 16); !ok {
		return nil, fmt.Errorf("bad serial %s", s)
	}
	// increment file
	inc := new(big.Int).Add(n, big.NewInt(1))
	os.WriteFile(filepath.Join(PKIDir(), "serial"), []byte(fmt.Sprintf("%X\n", inc)), 0o644)
	return n, nil
}

// IssueClientCert issues a client certificate for cn. Returns cert PEM, key PEM.
func IssueClientCert(cn string) (string, string, error) {
	caCert, caKey, err := loadCA()
	if err != nil {
		return "", "", err
	}
	// generate key
	key, err := ecdsa.GenerateKey(caCert.PublicKey.(*ecdsa.PublicKey).Curve, rand.Reader)
	if err != nil {
		// use P-256
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", "", err
		}
	}
	serial, err := nextSerial()
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(1825 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	// append to index.txt
	appendIndex(cn, serial, now, tmpl.NotAfter, false)
	return string(certPEM), string(keyPEM), nil
}

func appendIndex(cn string, serial *big.Int, notBefore, notAfter time.Time, revoked bool) {
	// OpenSSL ca format: status \t expiry \t [revocation] \t serial \t unknown \t /CN=cn
	status := "V"
	expiry := notAfter.UTC().Format("060102150405Z")
	line := status + "\t" + expiry + "\t\t" + fmt.Sprintf("%X", serial) + "\tunknown\t/CN=" + cn + "\n"
	f, err := os.OpenFile(filepath.Join(PKIDir(), "index.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(line)
}

// RevokeCert marks a cert revoked and regenerates CRL.
func RevokeCert(serialHex string) error {
	// mark index.txt row
	path := filepath.Join(PKIDir(), "index.txt")
	data, _ := os.ReadFile(path)
	lines := strings.Split(string(data), "\n")
	now := time.Now().UTC().Format("060102150405Z")
	var out []string
	for _, ln := range lines {
		fields := strings.Split(ln, "\t")
		if len(fields) >= 4 && strings.EqualFold(fields[3], serialHex) && fields[0] == "V" {
			// status R, add revocation time
			if len(fields) < 3 {
				fields = append(fields, "")
			}
			fields[0] = "R"
			fields[2] = now
			out = append(out, strings.Join(fields, "\t"))
			continue
		}
		out = append(out, ln)
	}
	os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o644)
	return GenerateCRL()
}

// GenerateCRL writes crl.pem using Go crypto/x509.
func GenerateCRL() error {
	caCert, caKey, err := loadCA()
	if err != nil {
		return err
	}
	// parse revoked entries from index.txt
	data, _ := os.ReadFile(filepath.Join(PKIDir(), "index.txt"))
	var revoked []pkix.RevokedCertificate
	for _, ln := range strings.Split(string(data), "\n") {
		fields := strings.Split(ln, "\t")
		if len(fields) < 4 || fields[0] != "R" {
			continue
		}
		serial := new(big.Int)
		if _, ok := serial.SetString(fields[3], 16); !ok {
			continue
		}
		// revocation time fields[2]
		rt, err := time.Parse("060102150405Z", fields[2])
		if err != nil {
			rt = time.Now()
		}
		revoked = append(revoked, pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: rt,
		})
	}
	// crl number
	crlNum := big.NewInt(4096)
	if data, err := os.ReadFile(filepath.Join(PKIDir(), "crlnumber")); err == nil {
		n := new(big.Int)
		if _, ok := n.SetString(strings.TrimSpace(string(data)), 16); ok {
			crlNum = n
			// increment
			inc := new(big.Int).Add(n, big.NewInt(1))
			os.WriteFile(filepath.Join(PKIDir(), "crlnumber"), []byte(fmt.Sprintf("%X\n", inc)), 0o644)
		}
	}
	now := time.Now()
	tmpl := &x509.RevocationList{
		Number:              crlNum,
		ThisUpdate:          now,
		NextUpdate:          now.Add(365 * 24 * time.Hour),
		RevokedCertificates: revoked,
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, caKey)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	os.WriteFile(CRLFile(), pemBytes, 0o644)
	os.Chmod(CRLFile(), 0o644)
	return nil
}

// RenewServerCertificateNative renews server cert.
func RenewServerCertificateNative() error {
	caCert, caKey, err := loadCA()
	if err != nil {
		return err
	}
	// archive old
	oldCert, _ := os.ReadFile(ServerCert())
	if oldCert != nil {
		os.MkdirAll(filepath.Join(PKIDir(), "renewed"), 0o755)
		os.WriteFile(filepath.Join(PKIDir(), "renewed", "server.crt.bak"), oldCert, 0o644)
	}
	key, err := ecdsa.GenerateKey(caCert.PublicKey.(*ecdsa.PublicKey).Curve, rand.Reader)
	if err != nil {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
	}
	serial, err := nextSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(1825 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"server"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(ServerCert()), 0o755)
	os.WriteFile(ServerCert(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	os.MkdirAll(filepath.Dir(ServerKey()), 0o755)
	os.WriteFile(ServerKey(), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	appendIndex("server", serial, now, tmpl.NotAfter, false)
	return nil
}

// unused import guard
