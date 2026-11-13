// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package hooks implements the OpenVPN client hooks. A non-zero exit refuses
// the client; the decision must work with the agent down, so it reads disk.
//
// The log tokens ("is disabled", "USERS_DIR missing", "REJECT", "FAILED") are
// a contract with the panel. Keep them.
package hooks

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"crypto/rand"
	"encoding/hex"
	"ovnode/internal/config"
	"ovnode/internal/events"
	"ovnode/internal/fsx"
	"ovnode/internal/logging"
	"ovnode/internal/ovpn"
	"ovnode/internal/settings"
	"ovnode/internal/store"
)

// Connect is the client-connect policy: 0 admits, 1 refuses. Limit 0 is
// unlimited, limit 1 takes over, and N > 1 follows the node policy. A down
// management socket degrades to a temporary extra, never a refused reconnect.

// overflowReserve is the single temporary session reserve mode admits for a
// reconnect. The background reaper returns the count to the limit once the
// stale row expires.
const overflowReserve = 1

func Connect(cfg config.Hook, arg string) int {
	exit := connectDecision(cfg, arg)
	_ = events.NotifyHook("connect", hookEventCN(arg))
	return exit
}

// connectDecision is the original Connect body; the wrapper keeps the
// notify send off every return path.
// hookEventCN resolves the common name the same way the hooks do; empty is
// fine — any hook fire still makes the agent republish its snapshot.
func hookEventCN(arg string) string {
	if cn := os.Getenv("common_name"); cn != "" {
		return cn
	}
	return arg
}

func connectDecision(cfg config.Hook, arg string) int {
	cn := os.Getenv("common_name")
	if cn == "" {
		cn = arg
	}
	trustedIP := os.Getenv("trusted_ip")
	trustedPort := os.Getenv("trusted_port")
	poolIP := os.Getenv("ifconfig_pool_remote_ip")

	safeCN := Sanitize(cn)
	safeIP := Sanitize(orUnknown(trustedIP))
	safePort := Sanitize(orUnknown(trustedPort))

	if !validHookCN(cn, safeCN) {
		logging.Event(cfg.LogFile, "CN=%s (sanitized=%s) rejected: malformed; REJECT", safeCN, safeCN)
		return 1
	}

	// Fail closed when the user tree is missing or unreadable: denying the
	// connection beats risking an allowed disabled user. The agent creates
	// the tree at startup, so its absence means a filesystem problem.
	if info, err := os.Stat(cfg.UsersDir); err != nil || !info.IsDir() {
		logging.Event(cfg.LogFile,
			"CN=%s ip=%s:%s; USERS_DIR missing or not a directory — fail-closed; REJECT",
			safeCN, safeIP, safePort)
		return 1
	}
	if err := fsx.MkdirAllNoFollow(cfg.SessionsDir, 0o770); err != nil {
		logging.Event(cfg.LogFile, "CN=%s could not prepare session directory: %v; REJECT", safeCN, err)
		return 1
	}

	state, err := store.ReadUserState(cfg.UsersDir, safeCN)
	if err != nil {
		logging.Event(cfg.LogFile, "CN=%s could not read user state: %v; REJECT", safeCN, err)
		return 1
	}
	limit := config.DefaultLimit
	if state.LimitSet {
		limit = state.Limit
	}
	if state.Disabled {
		logging.Event(cfg.LogFile, "CN=%s ip=%s:%s is disabled; REJECT",
			safeCN, safeIP, safePort)
		return 1
	}
	poolKey := ""
	if poolIP != "" {
		poolKey = Sanitize(poolIP)
	}
	key := store.SessionKey(safeCN, poolKey,
		Sanitize(orUnknown(trustedIP)), Sanitize(orUnknown(trustedPort)))

	// Actual hook connection start (OpenVPN time_unix), fallback to now.
	connStart := hookTimeUnix()

	if limit == 0 {
		// Unlimited still gets an accounting marker, under the session
		// lock so a delayed disconnect cannot interleave.
		marker := newMarker(safeCN, trustedIP, trustedPort, poolIP, key, connStart)
		if err := store.Lock(filepath.Join(cfg.SessionsDir, ".lock."+safeCN), 0o660, func() error {
			if err := bankDisplacedGeneration(cfg, safeCN, key, poolIP,
				liveRows(ovpn.SessionsForCN(cfg.StatusFile, safeCN))); err != nil {
				return err
			}
			return store.WriteMarker(filepath.Join(cfg.SessionsDir, key), marker)
		}); err != nil {
			logging.Event(cfg.LogFile, "CN=%s could not write the session marker: %v; REJECT", safeCN, err)
			return 1
		}
		logging.Event(cfg.LogFile, "CN=%s limit=unlimited; LOCAL_ALLOW", safeCN)
		return 0
	}

	// Every critical section below is CN-scoped: a global lock would
	// serialize unrelated users behind a reconnect storm.
	lockPath := filepath.Join(cfg.SessionsDir, ".lock."+safeCN)
	var exit int
	if err := store.Lock(lockPath, 0o660, func() error {
		exit = connectLocked(cfg, cn, safeCN, trustedIP, trustedPort, poolIP, key, limit, connStart)
		return nil
	}); err != nil {
		// Without the lock two sessions of the same user could pass the
		// limit check at once. Refuse rather than guess.
		logging.Event(cfg.LogFile, "CN=%s could not take the session lock: %v; REJECT", safeCN, err)
		return 1
	}
	return exit
}

func validHookCN(cn, safeCN string) bool {
	// Reject CNs whose sanitized form differs, so distinct names cannot
	// collapse onto one store entry / limit / disabled flag.
	return safeCN == cn && HookCNValid(safeCN)
}

// filterSelf drops the live row that is this very connection: same real
// address/port or same pool address.
func filterSelf(sessions []ovpn.Session, trustedIP, trustedPort, poolIP string) []ovpn.Session {
	out := sessions[:0]
	for _, s := range sessions {
		if trustedIP != "" && s.TrustedIP == trustedIP &&
			(trustedPort == "" || s.TrustedPort == trustedPort) {
			continue
		}
		if poolIP != "" && s.VirtualAddress == poolIP {
			continue
		}
		out = append(out, s)
	}
	return out
}

func newMarker(safeCN, trustedIP, trustedPort, poolIP, key string, connStart int64) store.Marker {
	return store.Marker{
		CommonName:  safeCN,
		TrustedIP:   trustedIP,
		TrustedPort: trustedPort,
		PoolIP:      poolIP,
		Created:     time.Now().Unix(),
		SessionID:   key + "." + newGeneration(),
		ConnectedAt: connStart,
	}
}

// liveSessions reads the per-protocol status files. The hook must not open
// the single management slot for admission; the agent owns that socket and
// handles any targeted kill asynchronously.
func liveSessions(cfg config.Hook, safeCN string) []ovpn.Session {
	return liveRows(ovpn.StatusSessionsForCN(cfg.StatusFile, safeCN))
}

// freshMarkerCount counts markers of this CN written in the marker window
// and absent from the live list: a connect accepted seconds ago is live
// before the status file or management has echoed it.
func freshMarkerCount(cfg config.Hook, safeCN string, sessions []ovpn.Session, ownKey string) int {
	seen := make(map[string]bool, len(sessions))
	for _, s := range sessions {
		if s.VirtualAddress != "" {
			seen[s.VirtualAddress] = true
		}
		if s.RealAddress != "" {
			seen[s.RealAddress] = true
		}
	}
	now := time.Now().Unix()
	count := 0
	entries, err := os.ReadDir(cfg.SessionsDir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == ownKey || !strings.HasPrefix(e.Name(), safeCN+".") {
			continue
		}
		m, ok := store.ReadMarker(filepath.Join(cfg.SessionsDir, e.Name()))
		if !ok || m.CommonName != safeCN {
			continue
		}
		created := m.Created
		if created == 0 {
			created = m.ConnectedAt
		}
		if created == 0 || now-created > 10 || now-created < -10 {
			continue
		}
		if seen[m.PoolIP] || seen[m.TrustedIP+":"+m.TrustedPort] {
			continue
		}
		count++
	}
	return count
}

// connectLocked is the policy under the per-CN lock.
func connectLocked(
	cfg config.Hook,
	cn, safeCN, trustedIP, trustedPort, poolIP, key string,
	limit int,
	connStart int64,
) int {
	safeIP := Sanitize(orUnknown(trustedIP))
	safePort := Sanitize(orUnknown(trustedPort))
	// One live read for the whole hook: the live session count of this
	// CN decides admission. Fresh markers the live list has not echoed yet
	// count as live too.
	// OpenVPN may already list the connection being admitted (client-connect
	// runs after the client row exists). Exclude this peer/pool; otherwise a
	// limit=1 user counts their own new session as the old one and is rejected
	// even when they are the only device.
	sessions := filterSelf(liveSessions(cfg, safeCN), trustedIP, trustedPort, poolIP)
	count := len(sessions) + freshMarkerCount(cfg, safeCN, sessions, key)

	if count >= limit {
		if limit == 1 {
			if !takeover(cfg, safeCN, trustedIP, trustedPort, poolIP, sessions, count) {
				return 1
			}
		} else {
			policy, err := loadLimitPolicy()
			if err != nil {
				logging.Event(cfg.LogFile,
					"CN=%s limit policy unreadable: %v; using reserve", safeCN, err)
				policy = settings.LimitReserve
			}
			switch policy {
			case settings.LimitStrict:
				logging.Event(cfg.LogFile,
					"CN=%s ip=%s:%s pool=%s limit=%d status=%d; REJECT (strict)",
					safeCN, safeIP, safePort, orNone(poolIP), limit, count)
				return 1
			case settings.LimitTakeover:
				if count >= limit+overflowReserve {
					logging.Event(cfg.LogFile,
						"CN=%s ip=%s:%s pool=%s limit=%d status=%d; REJECT (takeover cap)",
						safeCN, safeIP, safePort, orNone(poolIP), limit, count)
					return 1
				}
				target, ok := takeoverTarget(sessions, trustedIP)
				if !ok {
					logging.Event(cfg.LogFile,
						"CN=%s ip=%s:%s pool=%s limit=%d status=%d; REJECT (takeover, no target)",
						safeCN, safeIP, safePort, orNone(poolIP), limit, count)
					return 1
				}
				if err := queueKill(safeCN, target); err != nil {
					logging.Event(cfg.LogFile,
						"CN=%s ip=%s:%s pool=%s limit=%d status=%d; DEGRADE (takeover, queue failed: %v)",
						safeCN, safeIP, safePort, orNone(poolIP), limit, count, err)
				} else {
					logging.Event(cfg.LogFile,
						"CN=%s ip=%s:%s pool=%s limit=%d status=%d; TAKEOVER queued client-kill cid=%s",
						safeCN, safeIP, safePort, orNone(poolIP), limit, count, target.ClientID)
				}
			default:
				if count < limit+overflowReserve {
					logging.Event(cfg.LogFile,
						"CN=%s ip=%s:%s pool=%s limit=%d status=%d; ALLOW (overflow reserve +1)",
						safeCN, safeIP, safePort, orNone(poolIP), limit, count)
					break
				}
				newest, ok := newestSession(sessions)
				if ok && isDigits(newest.ClientID) && newest.BytesReceived+newest.BytesSent == 0 {
					_ = queueKill(safeCN, newest)
					logging.Event(cfg.LogFile,
						"CN=%s ip=%s:%s pool=%s limit=%d status=%d; RECLAIM queued client-kill cid=%s (zero-byte)",
						safeCN, safeIP, safePort, orNone(poolIP), limit, count, newest.ClientID)
				}
				logging.Event(cfg.LogFile,
					"CN=%s ip=%s:%s pool=%s limit=%d status=%d; REJECT (overflow cap)",
					safeCN, safeIP, safePort, orNone(poolIP), limit, count)
				return 1
			}
		}
	}

	marker := newMarker(safeCN, trustedIP, trustedPort, poolIP, key, connStart)
	// If this key holds a previous generation (takeover/pool reuse), bank
	// its last observed status bytes as closed before overwriting the
	// marker: the delayed disconnect of the old generation will be
	// identity-rejected and must not erase its final accounting.
	if err := bankDisplacedGeneration(cfg, safeCN, key, poolIP, sessions); err != nil {
		logging.Event(cfg.LogFile, "CN=%s takeover banking failed: %v; REJECT", safeCN, err)
		return 1
	}
	if err := store.WriteMarker(filepath.Join(cfg.SessionsDir, key), marker); err != nil {
		logging.Event(cfg.LogFile, "CN=%s could not write the session marker: %v; REJECT", safeCN, err)
		return 1
	}

	logging.Event(cfg.LogFile, "CN=%s ip=%s:%s pool=%s limit=%d status=%d; ALLOW session=%s",
		safeCN, safeIP, safePort, orNone(poolIP), limit, count, key)
	return 0
}

var (
	loadLimitPolicy = settings.LoadLimitPolicy
	notifyKill      = events.NotifyKill
)

// newestSession returns the most recently connected session that has a
// numeric management client id, the only id client-kill accepts.
func newestSession(sessions []ovpn.Session) (ovpn.Session, bool) {
	var best ovpn.Session
	found := false
	for _, s := range sessions {
		if !isDigits(s.ClientID) {
			continue
		}
		if !found || s.ConnectedAt > best.ConnectedAt ||
			(s.ConnectedAt == best.ConnectedAt && cidNumber(s.ClientID) > cidNumber(best.ClientID)) {
			best, found = s, true
		}
	}
	return best, found
}

// takeoverTarget prefers the reconnecting device's own old copy on the same
// trusted address, then the most recently connected session.
func takeoverTarget(sessions []ovpn.Session, trustedIP string) (ovpn.Session, bool) {
	if trustedIP != "" {
		var same []ovpn.Session
		for _, s := range sessions {
			if s.TrustedIP == trustedIP {
				same = append(same, s)
			}
		}
		if target, ok := newestSession(same); ok {
			return target, true
		}
	}
	return newestSession(sessions)
}

func cidNumber(cid string) int {
	n, _ := strconv.Atoi(cid)
	return n
}

// queueKill sends the stable identity; the agent resolves the virtual
// address to the current client id, so a stale status id cannot kill the new.
func queueKill(cn string, target ovpn.Session) error {
	return notifyKill(target.ClientID, target.Protocol, cn, target.VirtualAddress, target.RealAddress)
}

// bankDisplacedGeneration closes the previous generation at key before a new
// marker replaces it. Callers hold the per-CN lock; the offset dedupes.
func bankDisplacedGeneration(cfg config.Hook, safeCN, key, poolIP string, sessions []ovpn.Session) error {
	old, ok := store.ReadMarker(filepath.Join(cfg.SessionsDir, key))
	if !ok || old.SessionID == "" {
		return nil
	}
	var oldBytes uint64
	found := false
	for _, s := range sessions {
		if poolIP != "" && s.VirtualAddress == poolIP {
			oldBytes = s.BytesReceived + s.BytesSent
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	_, err := store.RecordSessionUsage(cfg.UsageDir, safeCN, old.SessionID, oldBytes, true)
	return err
}

// takeover queues a targeted client-kill for each old session and admits.
// The hook never calls kill <cn>, which would remove the new session too;
// the agent owns the management slot and retries.
func takeover(
	cfg config.Hook,
	safeCN, trustedIP, trustedPort, poolIP string,
	sessions []ovpn.Session,
	count int,
) bool {
	safeIP := Sanitize(orUnknown(trustedIP))
	safePort := Sanitize(orUnknown(trustedPort))
	targets := make([]ovpn.Session, 0, len(sessions))
	for _, s := range sessions {
		if isDigits(s.ClientID) {
			targets = append(targets, s)
		}
	}
	logging.Event(cfg.LogFile,
		"CN=%s ip=%s:%s pool=%s limit=1 status=%d; TAKEOVER (%d queued client-kill targets)",
		safeCN, safeIP, safePort, orNone(poolIP), count, len(targets))

	if len(targets) == 0 {
		logging.Event(cfg.LogFile,
			"CN=%s ip=%s:%s pool=%s limit=1 status=%d; DEGRADE (takeover, no numeric target)",
			safeCN, safeIP, safePort, orNone(poolIP), count)
		return true
	}
	for _, target := range targets {
		if err := queueKill(safeCN, target); err != nil {
			logging.Event(cfg.LogFile,
				"CN=%s ip=%s:%s pool=%s limit=1 status=%d; DEGRADE (takeover, queue failed: %v)",
				safeCN, safeIP, safePort, orNone(poolIP), count, err)
			return true
		}
		logging.Event(cfg.LogFile,
			"CN=%s ip=%s:%s pool=%s limit=1 status=%d; TAKEOVER queued client-kill cid=%s",
			safeCN, safeIP, safePort, orNone(poolIP), count, target.ClientID)
	}
	return true
}

// liveRows drops the rows the bash prefilter also dropped: a row with no
// pool address, no client id and no real address carries no session.
func liveRows(sessions []ovpn.Session) []ovpn.Session {
	var out []ovpn.Session
	for _, s := range sessions {
		// A connected client always has a pool address. Rows without one are
		// this very hook's pending client or a rejected attempt; counting
		// them would block the next login.
		if s.VirtualAddress == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func orUnknown(v string) string {
	if v == "" {
		return "?"
	}
	return v
}

func orNone(v string) string {
	if v == "" {
		return "none"
	}
	return v
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// hookTimeUnix is the actual connection start OpenVPN passes via time_unix
// (seconds since epoch); invalid/missing values fall back to now.
func hookTimeUnix() int64 {
	v := strings.TrimSpace(os.Getenv("time_unix"))
	if v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return time.Now().Unix()
}

func newGeneration() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Entropy failure must not break generation-safe matching ("0" is
		// not 16-hex); derive an 8-byte value from time + pid instead.
		return hex.EncodeToString([]byte(fmt.Sprintf("%d-%d-", time.Now().UnixNano(), os.Getpid()) + "x")[:8])
	}
	return hex.EncodeToString(b)
}
