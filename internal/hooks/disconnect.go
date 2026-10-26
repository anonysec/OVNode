// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ovnode/internal/config"
	"ovnode/internal/logging"
	"ovnode/internal/store"
)

// Disconnect is the client-disconnect hook.
//
// It removes the local session marker and banks the session's final byte
// counters into the per-user accumulator: OpenVPN exposes bytes_received and
// bytes_sent only here, so without this the traffic of a completed session
// would be lost between status-file polls.
//
// The exit code is always 0: the client is already gone, and a cleanup that
// failed must not turn into an error the daemon reports.
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
	poolKey := ""
	if poolIP != "" {
		poolKey = Sanitize(poolIP)
	}
	ipKey := Sanitize(orUnknown(trustedIP))
	portKey := Sanitize(orUnknown(trustedPort))
	key := store.SessionKey(safeCN, poolKey, ipKey, portKey)

	_ = os.MkdirAll(cfg.SessionsDir, 0o755)

	// Usage accounting under a dedicated usage lock, so a connect storm is
	// never head-of-line blocked behind accounting writes while two
	// simultaneous disconnects of the same CN still cannot lose an update.
	rx := counter("bytes_received")
	tx := counter("bytes_sent")
	if total := rx + tx; total > 0 {
		accumulated, ok := store.BankUsage(cfg.UsageDir, safeCN, total)
		if ok {
			logging.Syslog("CN=%s session ended rx=%d tx=%d accumulated=%d", cn, rx, tx, accumulated)
		} else {
			logging.Syslog("CN=%s usage accounting skipped (rx=%d tx=%d)", cn, rx, tx)
		}
	}

	_ = store.Lock(filepath.Join(cfg.SessionsDir, ".lock."+safeCN), func() error {
		sessionFile := filepath.Join(cfg.SessionsDir, key)
		if _, err := os.Stat(sessionFile); err == nil {
			_ = os.Remove(sessionFile)
			logging.Syslog("CN=%s disconnect removed session=%s", cn, key)
		} else {
			// Legacy layouts: CN.ip.port.pool (pre pool-IP keying).
			store.RemoveLegacyMarkers(cfg.SessionsDir, safeCN, poolKey, ipKey, portKey)
			logging.Syslog("CN=%s disconnect fallback cleanup session=%s", cn, key)
		}
		return nil
	})
	return 0
}

// counter reads a byte counter from the environment. A value that is not a
// plain number counts as zero.
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
