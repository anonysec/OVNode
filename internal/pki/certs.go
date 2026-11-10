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
	"sync"
	"time"
)

const CRLRenewThresholdDays = 30

var months = map[string]int{
	"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
	"Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

type crlCacheEntry struct {
	mtime     time.Time
	caMtime   time.Time
	days      int
	matchesCA bool
	crlExists bool
}

// crlCache is one small struct keyed by CRL file mtime. /sync/status
// calls all three CRL helpers on every poll; without this it re-reads
// and re-parses the same files each time. The CA mtime is folded in so
// a pushed CA invalidates the match result.
var crlCache struct {
	mu    sync.Mutex
	entry crlCacheEntry
	have  bool
}

func crlCacheCurrent() (crlCacheEntry, bool) {
	crlCache.mu.Lock()
	defer crlCache.mu.Unlock()
	if !crlCache.have {
		return crlCacheEntry{}, false
	}
	fi, err := os.Stat(CRLFile())
	if err != nil {
		if os.IsNotExist(err) && !crlCache.entry.crlExists {
			// A pushed CA invalidates the match result even when the CRL
			// is still missing.
			if ca, err := os.Stat(CACert()); err == nil && ca.ModTime().Equal(crlCache.entry.caMtime) {
				return crlCache.entry, true
			}
		}
		return crlCacheEntry{}, false
	}
	if !fi.ModTime().Equal(crlCache.entry.mtime) {
		return crlCacheEntry{}, false
	}
	if ca, err := os.Stat(CACert()); err != nil {
		return crlCacheEntry{}, false
	} else if !ca.ModTime().Equal(crlCache.entry.caMtime) {
		return crlCacheEntry{}, false
	}
	return crlCache.entry, true
}

func crlCacheStore(e crlCacheEntry) {
	crlCache.mu.Lock()
	defer crlCache.mu.Unlock()
	crlCache.entry = e
	crlCache.have = true
}

// CRLDaysRemaining returns days until CRL nextUpdate, or -1 if unreadable.
// The result is cached by CRL file mtime.
func CRLDaysRemaining() int {
	if e, ok := crlCacheCurrent(); ok && e.crlExists {
		return e.days
	}
	out, err := exec.Command("openssl", "crl", "-nextupdate", "-noout", "-in", CRLFile()).Output()
	if err != nil {
		return -1
	}
	d := DaysUntilOpensslDate(string(out))
	if d == nil {
		return -1
	}
	if fi, err := os.Stat(CRLFile()); err == nil {
		e := crlCacheEntry{mtime: fi.ModTime(), days: *d, crlExists: true}
		if ca, err := os.Stat(CACert()); err == nil {
			e.caMtime = ca.ModTime()
		}
		if prev, ok := crlCacheCurrent(); ok {
			e = prev
			e.days = *d
			e.mtime = fi.ModTime()
			e.crlExists = true
		}
		crlCacheStore(e)
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
	if e, ok := crlCacheCurrent(); ok {
		return e.matchesCA
	}
	if _, err := os.Stat(CRLFile()); err != nil {
		res := os.IsNotExist(err)
		e := crlCacheEntry{matchesCA: res}
		if ca, err := os.Stat(CACert()); err == nil {
			e.caMtime = ca.ModTime()
		}
		crlCacheStore(e)
		return res
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
	res := crl.CheckSignatureFrom(cert) == nil
	if fi, err := os.Stat(CRLFile()); err == nil {
		e := crlCacheEntry{mtime: fi.ModTime(), matchesCA: res, crlExists: true}
		if ca, err := os.Stat(CACert()); err == nil {
			e.caMtime = ca.ModTime()
		}
		if prev, ok := crlCacheCurrent(); ok {
			e.matchesCA = res
			e.days = prev.days
		}
		crlCacheStore(e)
	}
	return res
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
