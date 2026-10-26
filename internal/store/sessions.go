// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"fmt"
	"os"
	"path/filepath"

	"ovnode/internal/fsx"
	"strconv"
	"strings"
)

// Marker is one live session marker.
type Marker struct {
	CommonName  string
	TrustedIP   string
	TrustedPort string
	PoolIP      string
	Created     int64
}

// SessionKey is the marker file name of a session: the CN plus the VPN pool
// IP, which is stable for the session lifetime in dynamic-IP environments
// where the real address changes on every reconnect.
//
// Without a pool IP (a rare hook-order edge case) the real address is used
// instead, so two concurrent no-pool sessions cannot share a key.
func SessionKey(safeCN, poolIP, trustedIP, trustedPort string) string {
	if poolIP != "" {
		return safeCN + "." + poolIP
	}
	return safeCN + ".noip." + trustedIP + "." + trustedPort
}

// WriteMarker writes the marker file. It is world-unreadable: it names the
// real address of the client.
func WriteMarker(path string, m Marker) error {
	body := fmt.Sprintf(
		"common_name=%s\ntrusted_ip=%s\ntrusted_port=%s\nifconfig_pool_remote_ip=%s\ncreated=%d\n",
		m.CommonName, m.TrustedIP, m.TrustedPort, m.PoolIP, m.Created,
	)
	return fsx.WriteFileAtomic(path, []byte(body), 0o600)
}

// ReadMarker parses a marker file. A missing file is not an error the
// caller needs to distinguish: it means "no marker".
func ReadMarker(path string) (Marker, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Marker{}, false
	}
	m := Marker{}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "common_name":
			m.CommonName = v
		case "trusted_ip":
			m.TrustedIP = v
		case "trusted_port":
			m.TrustedPort = v
		case "ifconfig_pool_remote_ip":
			m.PoolIP = v
		case "created":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				m.Created = n
			}
		}
	}
	return m, true
}

// RemoveMarkers removes every session marker of one CN.
//
// At limit=1 the node keeps a single session per user, so the new marker
// replaces the old ones instead of accumulating.
func RemoveMarkers(sessionsDir, safeCN string) {
	prefix := safeCN + "."
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if e.IsDir() {
			continue
		}
		_ = os.Remove(filepath.Join(sessionsDir, name))
	}
}

// RemoveLegacyMarkers removes the pre pool-IP marker names of one CN:
// "<cn>.<ip>.<port>.<pool>" and "<cn>.*.<pool>".
func RemoveLegacyMarkers(sessionsDir, safeCN, poolIP, trustedIP, trustedPort string) {
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		legacyAddr := safeCN + "." + trustedIP + "." + trustedPort + "."
		legacyPool := ""
		if poolIP != "" {
			legacyPool = "." + poolIP
		}
		if strings.HasPrefix(name, legacyAddr) ||
			(legacyPool != "" && strings.HasPrefix(name, safeCN+".") && strings.HasSuffix(name, legacyPool)) {
			_ = os.Remove(filepath.Join(sessionsDir, name))
		}
	}
}
