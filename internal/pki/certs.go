// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const CRLRenewThresholdDays = 30

var months = map[string]int{
	"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
	"Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

// CRLDaysRemaining returns days until CRL nextUpdate, or -1 if unreadable.
func CRLDaysRemaining() int {
	out, err := exec.Command("openssl", "crl", "-nextupdate", "-noout", "-in", CRLFile()).Output()
	if err != nil {
		return -1
	}
	d := DaysUntilOpensslDate(string(out))
	if d == nil {
		return -1
	}
	return *d
}

// DaysUntilOpensslDate parses 'nextUpdate=Aug 28 ... GMT' -> days.
func DaysUntilOpensslDate(raw string) *int {
	value := ""
	if idx := strings.Index(raw, "="); idx >= 0 {
		value = strings.TrimSpace(raw[idx+1:])
	} else {
		value = strings.TrimSpace(raw)
	}
	parts := strings.Fields(value)
	if len(parts) < 5 {
		return nil
	}
	monthS, dayS, timeS, yearS := parts[0], parts[1], parts[2], parts[3]
	hms := strings.Split(timeS, ":")
	if len(hms) != 3 {
		return nil
	}
	m, ok := months[monthS]
	if !ok {
		return nil
	}
	day, _ := strconv.Atoi(dayS)
	year, _ := strconv.Atoi(yearS)
	hour, _ := strconv.Atoi(hms[0])
	min, _ := strconv.Atoi(hms[1])
	sec, _ := strconv.Atoi(hms[2])
	expiry := time.Date(year, time.Month(m), day, hour, min, sec, 0, time.UTC)
	days := int(expiry.Sub(time.Now().UTC()).Seconds() / 86400)
	return &days
}

// RenewServerCertificate renews the server cert via easyrsa.
func RenewServerCertificate() bool {
	if _, err := os.Stat(ServerCert()); err != nil {
		return false
	}
	if !RunEasyRSA("renew", "server", "nopass") {
		return false
	}
	return true
}

// EnsureCRL generates/renews CRL as needed.
func EnsureCRL() bool {
	return EnsureCRLChecked() == nil
}

func EnsureCRLChecked() error {
	if _, err := readIndex(); err != nil {
		return err
	}
	caPEM, err := os.ReadFile(CACert())
	if err != nil {
		return err
	}
	ca, err := ValidateCA(string(caPEM))
	if err != nil {
		return err
	}
	list, err := readCRL()
	if err == nil {
		if err := list.CheckSignatureFrom(ca); err != nil {
			return fmt.Errorf("existing CRL does not match the CA: %w", err)
		}
		if time.Until(list.NextUpdate) > CRLRenewThresholdDays*24*time.Hour {
			return os.Chmod(CRLFile(), 0o644)
		}
		return GenerateCRL()
	}
	if !os.IsNotExist(err) {
		return err
	}
	if err := RunEasyRSAChecked("gen-crl"); err != nil {
		return err
	}
	list, err = readCRL()
	if err != nil {
		return err
	}
	if err := list.CheckSignatureFrom(ca); err != nil {
		return err
	}
	return os.Chmod(CRLFile(), 0o644)
}

// CRLMatchesCA reports whether the local CRL was signed by the current CA.
//
// A pushed CA replaces ca.crt but leaves the old crl.pem behind; OpenVPN's
// crl-verify then rejects every client. Returning true when no CRL exists
// keeps a fresh node from being reported as mismatched.
func CRLMatchesCA() bool {
	if _, err := os.Stat(CRLFile()); err != nil {
		return os.IsNotExist(err)
	}
	crlPEM, err := os.ReadFile(CRLFile())
	if err != nil {
		return false
	}
	crlBlock, _ := pem.Decode(crlPEM)
	if crlBlock == nil {
		return false
	}
	crl, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		return false
	}
	caPEM, err := os.ReadFile(CACert())
	if err != nil {
		return false
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return false
	}
	cert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return false
	}
	return crl.CheckSignatureFrom(cert) == nil
}

// ReadTLSCryptKey returns the tls-crypt key or "".
func ReadTLSCryptKey() string {
	data, err := os.ReadFile(TLSKey())
	if err != nil {
		return ""
	}
	key := strings.TrimSpace(string(data))
	return key
}
