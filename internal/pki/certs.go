// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pki

import (
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
	if _, err := os.Stat(CRLFile()); err == nil {
		days := CRLDaysRemaining()
		if days >= 0 && days > CRLRenewThresholdDays {
			os.Chmod(CRLFile(), 0o644)
			return true
		}
		// regenerate
		if !RunEasyRSA("gen-crl") {
			if days >= 0 && days > 0 {
				return true
			}
			return false
		}
		os.Chmod(CRLFile(), 0o644)
		return true
	}
	if !RunEasyRSA("gen-crl") {
		return false
	}
	if _, err := os.Stat(CRLFile()); err != nil {
		return false
	}
	os.Chmod(CRLFile(), 0o644)
	return true
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
