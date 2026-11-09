// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"

	"ovnode/internal/fsx"
	"path/filepath"
	"strings"
	"time"
)

// loadCA loads the CA cert and private key (PKCS#8 per V3).
func loadCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, key, err := loadCASigner()
	if err != nil {
		return nil, nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA key is not ECDSA")
	}
	return cert, ecKey, nil
}

func loadCASigner() (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(CACert())
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(PKIDir(), "private", "ca.key"))
	if err != nil {
		return nil, nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	key, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("CA key cannot sign")
	}
	return cert, key, nil
}

// nextSerial reads serial file (hex) and increments it.
func nextSerial() (*big.Int, error) {
	data, err := os.ReadFile(filepath.Join(PKIDir(), "serial"))
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(data))
	n, err := hexNumber(s)
	if err != nil {
		return nil, err
	}
	// increment file
	inc := new(big.Int).Add(n, big.NewInt(1))
	if err := fsx.WriteFileAtomic(filepath.Join(PKIDir(), "serial"), []byte(fmt.Sprintf("%X\n", inc)), 0o644); err != nil {
		return nil, err
	}
	return n, nil
}

// IssueClientCert issues a client certificate for cn. Returns cert PEM, key PEM.
func IssueClientCert(cn string) (string, string, error) {
	return issueClientCert(cn, nil)
}

func issueClientCert(cn string, existingKey []byte) (string, string, error) {
	caCert, caKey, err := loadCA()
	if err != nil {
		return "", "", err
	}
	var key *ecdsa.PrivateKey
	if existingKey != nil {
		block, rest := pem.Decode(existingKey)
		if block == nil || strings.TrimSpace(string(rest)) != "" {
			return "", "", fmt.Errorf("invalid existing client key")
		}
		if block.Type == "EC PRIVATE KEY" {
			key, err = x509.ParseECPrivateKey(block.Bytes)
		} else {
			var parsed any
			parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			key, _ = parsed.(*ecdsa.PrivateKey)
		}
		if err != nil {
			return "", "", err
		}
		if key == nil {
			return "", "", fmt.Errorf("existing client key is not ECDSA")
		}
	} else {
		key, err = ecdsa.GenerateKey(caCert.PublicKey.(*ecdsa.PublicKey).Curve, rand.Reader)
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
	if existingKey != nil {
		keyPEM = existingKey
	}
	// append to index.txt
	if err := appendIndex(cn, serial, now, tmpl.NotAfter, false); err != nil {
		return "", "", err
	}
	return string(certPEM), string(keyPEM), nil
}

func appendIndex(cn string, serial *big.Int, notBefore, notAfter time.Time, revoked bool) error {
	// OpenSSL ca format: status \t expiry \t [revocation] \t serial \t unknown \t /CN=cn
	status := "V"
	expiry := notAfter.UTC().Format("060102150405Z")
	line := status + "\t" + expiry + "\t\t" + fmt.Sprintf("%X", serial) + "\tunknown\t/CN=" + cn + "\n"
	path := filepath.Join(PKIDir(), "index.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rows, err := parseIndex(data)
	if err != nil {
		return err
	}
	for _, row := range rows {
		n, _ := hexNumber(row[3])
		if n.Cmp(serial) == 0 {
			return fmt.Errorf("certificate serial %X already exists in the index", serial)
		}
	}
	if len(data) != 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, []byte(line)...)
	return fsx.WriteFileAtomic(path, data, 0o644)
}

// RevokeCert marks a cert revoked and regenerates CRL.
func RevokeCert(serialHex string) error {
	serial, err := hexNumber(serialHex)
	if err != nil {
		return err
	}
	rows, err := readIndex()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format("060102150405Z")
	found := false
	for _, row := range rows {
		n, _ := hexNumber(row[3])
		if n.Cmp(serial) == 0 {
			found = true
			if row[0] != "R" {
				row[0], row[2] = "R", now
			}
		}
	}
	if !found {
		return fmt.Errorf("certificate serial %s is not in the local index", serialHex)
	}
	if err := writeIndex(rows); err != nil {
		return err
	}
	return GenerateCRL()
}

// GenerateCRL writes crl.pem using Go crypto/x509.
func GenerateCRL() error {
	caCert, caKey, err := loadCASigner()
	if err != nil {
		return err
	}
	rows, err := readIndex()
	if err != nil {
		return err
	}
	var revoked []x509.RevocationListEntry
	seen := map[string]bool{}
	previous, err := readCRL()
	if err == nil {
		if err := previous.CheckSignatureFrom(caCert); err != nil {
			return fmt.Errorf("existing CRL does not match the local CA: %w", err)
		}
		for _, entry := range previous.RevokedCertificateEntries {
			revoked = append(revoked, entry)
			seen[entry.SerialNumber.Text(16)] = true
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, row := range rows {
		if row[0] != "R" {
			continue
		}
		entry, err := indexRevocation(row)
		if err != nil {
			return err
		}
		key := entry.SerialNumber.Text(16)
		if !seen[key] {
			revoked = append(revoked, entry)
			seen[key] = true
		}
	}
	crlNum := big.NewInt(4096)
	numberPath := filepath.Join(PKIDir(), "crlnumber")
	if data, err := os.ReadFile(numberPath); err == nil {
		crlNum, err = hexNumber(strings.TrimSpace(string(data)))
		if err != nil {
			return fmt.Errorf("invalid CRL number: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if previous != nil && previous.Number != nil && crlNum.Cmp(previous.Number) <= 0 {
		crlNum = new(big.Int).Add(previous.Number, big.NewInt(1))
	}
	now := time.Now()
	tmpl := &x509.RevocationList{
		Number:                    crlNum,
		ThisUpdate:                now,
		NextUpdate:                now.Add(365 * 24 * time.Hour),
		RevokedCertificateEntries: revoked,
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, caKey)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	inc := new(big.Int).Add(crlNum, big.NewInt(1))
	if err := fsx.WriteFileAtomic(numberPath, []byte(fmt.Sprintf("%X\n", inc)), 0o644); err != nil {
		return err
	}
	if err := fsx.WriteFileAtomic(CRLFile(), pemBytes, 0o644); err != nil {
		return err
	}
	dir, err := os.Open(PKIDir())
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func hexNumber(value string) (*big.Int, error) {
	if value == "" {
		return nil, fmt.Errorf("empty hexadecimal value")
	}
	for _, ch := range value {
		if !(ch >= '0' && ch <= '9' || ch >= 'A' && ch <= 'F' || ch >= 'a' && ch <= 'f') {
			return nil, fmt.Errorf("invalid hexadecimal value %q", value)
		}
	}
	n, ok := new(big.Int).SetString(value, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hexadecimal value %q", value)
	}
	return n, nil
}

func readIndex() ([][]string, error) {
	data, err := os.ReadFile(filepath.Join(PKIDir(), "index.txt"))
	if err != nil {
		return nil, err
	}
	return parseIndex(data)
}

func parseIndex(data []byte) ([][]string, error) {
	var rows [][]string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 6 || fields[5] == "" || (fields[0] != "V" && fields[0] != "R" && fields[0] != "E") {
			return nil, fmt.Errorf("malformed certificate index row %q", line)
		}
		serial, err := hexNumber(fields[3])
		if err != nil {
			return nil, err
		}
		if seen[serial.Text(16)] {
			return nil, fmt.Errorf("duplicate certificate index serial %s", fields[3])
		}
		seen[serial.Text(16)] = true
		if _, err := indexTime(fields[1]); err != nil {
			return nil, err
		}
		if fields[0] == "R" {
			if _, err := indexRevocation(fields); err != nil {
				return nil, err
			}
		} else if fields[2] != "" {
			return nil, fmt.Errorf("unexpected revocation date on a %s index row", fields[0])
		}
		rows = append(rows, fields)
	}
	return rows, nil
}

func writeIndex(rows [][]string) error {
	var body strings.Builder
	for _, row := range rows {
		body.WriteString(strings.Join(row, "\t"))
		body.WriteByte('\n')
	}
	return fsx.WriteFileAtomic(filepath.Join(PKIDir(), "index.txt"), []byte(body.String()), 0o644)
}

func indexTime(value string) (time.Time, error) {
	for _, layout := range []string{"060102150405Z", "20060102150405Z"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid certificate index time %q", value)
}

func indexRevocation(row []string) (x509.RevocationListEntry, error) {
	entry := x509.RevocationListEntry{}
	serial, err := hexNumber(row[3])
	if err != nil {
		return entry, err
	}
	date, reason, _ := strings.Cut(row[2], ",")
	revokedAt, err := indexTime(date)
	if err != nil {
		return entry, err
	}
	reasons := map[string]int{"": 0, "unspecified": 0, "keyCompromise": 1, "CACompromise": 2, "affiliationChanged": 3, "superseded": 4, "cessationOfOperation": 5, "certificateHold": 6, "privilegeWithdrawn": 9, "AACompromise": 10}
	code, ok := reasons[reason]
	if !ok {
		return entry, fmt.Errorf("unsupported certificate revocation reason %q", reason)
	}
	return x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revokedAt, ReasonCode: code}, nil
}

func readCRL() (*x509.RevocationList, error) {
	data, err := os.ReadFile(CRLFile())
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "X509 CRL" || strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("invalid CRL PEM at %s", CRLFile())
	}
	return x509.ParseRevocationList(block.Bytes)
}

// PrimaryIP returns the host's outbound IPv4 address for certificate SANs.
// The httpapi agent reuses this for its one-time setup print.
func PrimaryIP() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 2*time.Second)
	if err == nil {
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
			return addr.IP.String()
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "127.0.0.1"
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
		_ = fsx.WriteFileAtomic(filepath.Join(PKIDir(), "renewed", "server.crt.bak"), oldCert, 0o644)
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
	// Carry the node address as a SAN so clients and panels that validate
	// the certificate against the address (rather than only the CN) accept
	// the renewed server certificate.
	sanIPs := []net.IP{}
	if ip := net.ParseIP(PrimaryIP()); ip != nil {
		sanIPs = append(sanIPs, ip)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(1825 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"server", "localhost"},
		IPAddresses:  sanIPs,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	// verify cert matches key before writing
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(ServerCert()), 0o700)
	os.MkdirAll(filepath.Dir(ServerKey()), 0o700)
	// Write the key first, then the cert.
	if err := fsx.WriteFileAtomic(ServerKey(), keyPEM, 0o600); err != nil {
		return err
	}
	if err := fsx.WriteFileAtomic(ServerCert(), certPEM, 0o644); err != nil {
		return err
	}
	if err := appendIndex("server", serial, now, tmpl.NotAfter, false); err != nil {
		return err
	}
	return nil
}

// unused import guard
