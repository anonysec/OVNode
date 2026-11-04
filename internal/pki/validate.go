// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

const maxPEMField = 16 * 1024

// CleanPEM decodes a single PEM block and re-encodes it, stripping
// trailing garbage and normalizing whitespace.
func CleanPEM(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty PEM")
	}
	if len(s) > maxPEMField {
		return "", fmt.Errorf("PEM exceeds %d bytes", maxPEMField)
	}
	block, rest := pem.Decode([]byte(s))
	if block == nil {
		return "", fmt.Errorf("invalid PEM")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return "", fmt.Errorf("trailing garbage in PEM")
	}
	return string(pem.EncodeToMemory(block)), nil
}

func parseCert(s string) (*x509.Certificate, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty certificate")
	}
	if len(s) > maxPEMField {
		return nil, fmt.Errorf("certificate exceeds %d bytes", maxPEMField)
	}
	block, rest := pem.Decode([]byte(s))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("trailing garbage in certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate expired or not yet valid")
	}
	return cert, nil
}

// ValidateCA checks that s is a CA certificate.
func ValidateCA(s string) (*x509.Certificate, error) {
	cert, err := parseCert(s)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA")
	}
	return cert, nil
}

// ValidateServerCert validates pushed CA/cert/key material.
func ValidateServerCert(caPEM, certPEM, keyPEM string) error {
	for _, f := range []string{caPEM, certPEM, keyPEM} {
		if len(f) > maxPEMField {
			return fmt.Errorf("field exceeds %d bytes", maxPEMField)
		}
	}
	caCert, err := ValidateCA(caPEM)
	if err != nil {
		return err
	}
	cert, err := parseCert(certPEM)
	if err != nil {
		return err
	}
	// key matches cert
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return fmt.Errorf("key does not match certificate: %w", err)
	}
	// cert chains to CA
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		return fmt.Errorf("certificate does not chain to CA: %w", err)
	}
	return nil
}

// ValidateClientCert validates pushed client cert/key against cn and optional CA.
func ValidateClientCert(cn, certPEM, keyPEM, caPEM string) error {
	for _, f := range []string{certPEM, keyPEM, caPEM} {
		if len(f) > maxPEMField {
			return fmt.Errorf("field exceeds %d bytes", maxPEMField)
		}
	}
	cert, err := parseCert(certPEM)
	if err != nil {
		return err
	}
	if cert.Subject.CommonName != cn {
		return fmt.Errorf("client certificate CN %q does not match %q", cert.Subject.CommonName, cn)
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return fmt.Errorf("key does not match certificate: %w", err)
	}
	if caPEM != "" {
		caCert, err := ValidateCA(caPEM)
		if err != nil {
			return err
		}
		if err := cert.CheckSignatureFrom(caCert); err != nil {
			return fmt.Errorf("certificate does not chain to CA: %w", err)
		}
	}
	return nil
}
