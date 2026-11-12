// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package hooks implements the OpenVPN client hooks.
//
// The hook decides admission: a non-zero exit refuses the client. It must
// reach that decision with the agent daemon down, so everything it needs is
// on disk or on the management socket.
//
// The text of the log lines is a contract with the panel: backend/openvpn/
// sessions.py reads the event file and classifies each line, so the tokens
// ("is disabled", "USERS_DIR missing", "could not verify", "management
// unavailable", "REJECT", "FAILED") must survive the port.
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
	"ovnode/internal/store"
)

// Connect is the client-connect policy.
//
// Exit code 0 admits the client, 1 refuses it.
//
// Policy, on the live session count only:
//
//   - limit 0: unlimited, admit.
//   - disabled: refuse.
//   - limit 1 at the limit: take over the old session, then admit.
//   - limit N > 1 at the limit: refuse.
//
// The take-over never refuses a client because the management socket was
// down: a transient double session is cheaper than a refused reconnect.
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

// liveSessions is the hook's one live-session read: the management socket
// when it answers, otherwise the status file.
func liveSessions(cfg config.Hook, safeCN string) []ovpn.Session {
	return liveRows(ovpn.LiveSessionsForCN(cfg.StatusFile, safeCN))
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
		if !ok {
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

// freshMarkerPresent reports whether any marker of this CN was written
// in the marker window. A fresh marker means the previous hook accepted a
// session seconds ago, so a dead management socket cannot prove the old
// session is gone.
func freshMarkerPresent(cfg config.Hook, safeCN string) bool {
	now := time.Now().Unix()
	entries, err := os.ReadDir(cfg.SessionsDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), safeCN+".") {
			continue
		}
		m, ok := store.ReadMarker(filepath.Join(cfg.SessionsDir, e.Name()))
		if !ok {
			continue
		}
		created := m.Created
		if created == 0 {
			created = m.ConnectedAt
		}
		if created == 0 || now-created > 10 || now-created < -10 {
			continue
		}
		return true
	}
	return false
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
		if limit != 1 {
			logging.Event(cfg.LogFile, "CN=%s ip=%s:%s pool=%s limit=%d status=%d; REJECT",
				safeCN, safeIP, safePort, orNone(poolIP), limit, count)
			return 1
		}
		if !takeover(cfg, cn, safeCN, trustedIP, trustedPort, poolIP, sessions, count) {
			return 1
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

// bankDisplacedGeneration closes the previous generation at key with its
// last observed status bytes, if any, before a new marker replaces it.
// Callers hold the per-CN session lock (session lock before usage lock).
// Already-polled bytes are de-duplicated by the session offset.
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

// takeover kills the old session of a limit=1 user and reports whether the
// client may continue.
//
// False means the client is refused: the old session could not be verified
// as terminated. A management socket that is down is not a refusal — the
// markers are replaced and the corpse is reaped by ping-restart.
func takeover(
	cfg config.Hook,
	cn, safeCN, trustedIP, trustedPort, poolIP string,
	sessions []ovpn.Session,
	count int,
) bool {
	safeIP := Sanitize(orUnknown(trustedIP))
	safePort := Sanitize(orUnknown(trustedPort))
	var cids []string
	for _, s := range sessions {
		if isDigits(s.ClientID) {
			cids = append(cids, s.ClientID)
		}
	}
	logging.Event(cfg.LogFile,
		"CN=%s ip=%s:%s pool=%s limit=1 status=%d; TAKEOVER (%d mgmt cmds, one session)",
		safeCN, safeIP, safePort, orNone(poolIP), count, len(cids))

	// The sidecar is written BEFORE the attempt: the panel toasts the
	// displaced user on their next login, and a takeover that failed still
	// displaced somebody.
	sidecar := writeLastKill(cfg.UsersDir, safeCN, time.Now().Unix())
	logging.Event(cfg.LogFile, "CN=%s wrote kill sidecar=%s", safeCN, sidecar)

	result, lines := ovpn.Takeover(cfg.MgmtHost, cfg.MgmtPort, cfg.MgmtPassFile, cn, cids)
	for _, line := range lines {
		logging.Event(cfg.LogFile, "CN=%s mgmt: %s", safeCN, line)
	}

	switch result {
	case ovpn.TakeoverVerified:
		return true
	case ovpn.TakeoverTimeout:
		logging.Event(cfg.LogFile,
			"CN=%s ip=%s:%s pool=%s takeover could not verify old session termination; REJECT",
			cn, orUnknown(trustedIP), orUnknown(trustedPort), orNone(poolIP))
		return false
	default:
		if freshMarkerPresent(cfg, safeCN) {
			logging.Event(cfg.LogFile,
				"CN=%s ip=%s:%s pool=%s takeover could not verify old session termination; REJECT",
				cn, orUnknown(trustedIP), orUnknown(trustedPort), orNone(poolIP))
			return false
		}
		logging.Event(cfg.LogFile,
			"CN=%s ip=%s:%s pool=%s limit=1 status=%d; management unavailable; DEGRADE (markers replaced, corpse reaped by ping-restart)",
			cn, orUnknown(trustedIP), orUnknown(trustedPort), orNone(poolIP), count)
		return true
	}
}

// writeLastKill writes the kill-reason sidecar the panel reads to toast the
// displaced user. It returns the path it wrote.
func writeLastKill(usersDir, safeCN string, at int64) string {
	dir := filepath.Join(usersDir, safeCN)
	_ = os.MkdirAll(dir, 0o755) // #nosec G301 -- per-user state dir
	path := filepath.Join(dir, "last_kill.json")
	body := fmt.Sprintf(
		`{"reason":"replaced by newer session (limit=1)","at":%d,"cn":"%s","reason_code":"max_login_takeover"}`+"\n",
		at, safeCN)
	_ = fsx.WriteFileAtomic(path, []byte(body), 0o644)
	return path
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
