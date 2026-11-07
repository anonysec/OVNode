// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ovnode/internal/config"
	"ovnode/internal/fsx"
	"ovnode/internal/logging"
	"ovnode/internal/store"
)

// Disconnect is the client-disconnect hook.
//
// The marker's generation is identity-checked against this disconnect
// (connection start time_unix and trusted address): a delayed disconnect of
// a previous generation whose pool was reused must not bank into, or delete,
// the new generation's marker.
func Disconnect(cfg config.Hook, arg string) int {
	cn := os.Getenv("common_name")
	if cn == "" {
		cn = arg
	}
	if cn == "" {
		logging.Syslog("disconnect without common_name")
		return 0
	}

	trustedIP := os.Getenv("trusted_ip")
	trustedPort := os.Getenv("trusted_port")
	poolIP := os.Getenv("ifconfig_pool_remote_ip")

	safeCN := Sanitize(cn)
	if safeCN != cn || !HookCNValid(safeCN) {
		logging.Syslog("disconnect rejected malformed CN=%s", safeCN)
		return 0
	}
	poolKey := ""
	if poolIP != "" {
		poolKey = Sanitize(poolIP)
	}
	ipKey := Sanitize(orUnknown(trustedIP))
	portKey := Sanitize(orUnknown(trustedPort))
	key := store.SessionKey(safeCN, poolKey, ipKey, portKey)

	if err := fsx.MkdirAllNoFollow(cfg.SessionsDir, 0o770); err != nil {
		logging.Syslog("CN=%s could not prepare session directory: %v", safeCN, err)
		return 0
	}

	rx := counter("bytes_received")
	tx := counter("bytes_sent")
	sessionFile := filepath.Join(cfg.SessionsDir, key)

	if err := store.Lock(filepath.Join(cfg.SessionsDir, ".lock."+safeCN), 0o660, func() error {
		info, err := os.Stat(sessionFile)
		markerExists := err == nil && !info.IsDir()
		if !markerExists {
			// Legacy layouts: CN.ip.port.pool (pre pool-IP keying).
			store.RemoveLegacyMarkers(cfg.SessionsDir, safeCN, poolKey, ipKey, portKey)
			logging.Syslog("CN=%s disconnect fallback cleanup session=%s", safeCN, key)
			return nil
		}
		m, ok := store.ReadMarker(sessionFile)
		if !ok {
			return nil
		}
		if !disconnectMatches(m, key, trustedIP, trustedPort, hookTimeUnixEnv()) {
			logging.Syslog("CN=%s delayed disconnect for a previous generation; ignored session=%s", safeCN, key)
			return nil
		}
		sessionID := key
		if m.SessionID != "" {
			sessionID = m.SessionID
		}
		if _, err := store.RecordSessionUsage(cfg.UsageDir, safeCN, sessionID, rx+tx, true); err != nil {
			logging.Syslog("CN=%s usage accounting failed: %v", safeCN, err)
			// keep marker for retry
			return nil
		}
		if rx+tx > 0 {
			logging.Syslog("CN=%s session ended rx=%d tx=%d", safeCN, rx, tx)
		}
		if err := os.Remove(sessionFile); err != nil && !os.IsNotExist(err) {
			logging.Syslog("CN=%s marker removal failed: %v", safeCN, err)
			// receipt already recorded; retry is safe
		} else {
			logging.Syslog("CN=%s disconnect removed session=%s", safeCN, key)
		}
		return nil
	}); err != nil {
		logging.Syslog("CN=%s could not take the session lock: %v", safeCN, err)
	}
	return 0
}

// disconnectMatches reports whether the on-disk marker belongs to this
// disconnect.
//
// A v2 marker (generation-suffixed session ID) persisted the exact hook
// connection start: a differing time_unix, or a known trusted IP/port
// mismatch, proves this disconnect belongs to another generation —
// including a same-second replacement, where the trusted address is the
// only discriminator.
//
// A legacy marker persisted hook-run/creation time as connection_started,
// which may skew from the actual time_unix by a second; its evidence
// cannot prove a mismatch, so legacy final banking is tolerated. Missing
// values on either side likewise cannot prove a mismatch.
func disconnectMatches(m store.Marker, key, trustedIP, trustedPort string, startUnix int64) bool {
	sessionID := key
	if m.SessionID != "" {
		sessionID = m.SessionID
	}
	if !store.HasGeneration(sessionID) {
		return true
	}
	mStart := m.ConnectionStarted
	if mStart == 0 {
		mStart = m.ConnectedAt
	}
	if startUnix > 0 && mStart > 0 && startUnix != mStart {
		return false
	}
	if m.TrustedIP != "" && trustedIP != "" && m.TrustedIP != trustedIP {
		return false
	}
	if m.TrustedPort != "" && trustedPort != "" && m.TrustedPort != trustedPort {
		return false
	}
	return true
}

// hookTimeUnixEnv returns 0 when time_unix is absent/invalid (unknown start).
func hookTimeUnixEnv() int64 {
	v := strings.TrimSpace(os.Getenv("time_unix"))
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func counter(name string) uint64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return 0
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
