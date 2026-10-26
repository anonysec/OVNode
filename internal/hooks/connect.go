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
	"time"

	"ovnode/internal/config"
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
	cn := os.Getenv("common_name")
	if cn == "" {
		cn = arg
	}
	trustedIP := os.Getenv("trusted_ip")
	trustedPort := os.Getenv("trusted_port")
	poolIP := os.Getenv("ifconfig_pool_remote_ip")

	safeCN := Sanitize(cn)

	// Fail closed on malformed input.
	if !HookCNValid(safeCN) {
		logging.Event(cfg.LogFile, "CN=%s (sanitized=%s) rejected: malformed; REJECT", cn, safeCN)
		return 1
	}

	// Fail closed when the user tree is missing or unreadable: denying the
	// connection beats risking an allowed disabled user. The agent creates
	// the tree at startup, so its absence means a filesystem problem.
	if info, err := os.Stat(cfg.UsersDir); err != nil || !info.IsDir() {
		logging.Event(cfg.LogFile,
			"CN=%s ip=%s:%s; USERS_DIR missing or not a directory — fail-closed; REJECT",
			cn, orUnknown(trustedIP), orUnknown(trustedPort))
		return 1
	}
	if err := os.MkdirAll(cfg.SessionsDir, 0o755); err == nil {
		_ = os.Chmod(cfg.SessionsDir, 0o755)
	}

	state := store.ReadUserState(cfg.UsersDir, safeCN)
	limit := config.DefaultLimit
	if state.LimitSet {
		limit = state.Limit
	}
	if state.Disabled {
		logging.Event(cfg.LogFile, "CN=%s ip=%s:%s is disabled; REJECT",
			cn, orUnknown(trustedIP), orUnknown(trustedPort))
		return 1
	}
	if limit == 0 {
		logging.Event(cfg.LogFile, "CN=%s limit=unlimited; LOCAL_ALLOW", cn)
		return 0
	}

	poolKey := ""
	if poolIP != "" {
		poolKey = Sanitize(poolIP)
	}
	key := store.SessionKey(safeCN, poolKey,
		Sanitize(orUnknown(trustedIP)), Sanitize(orUnknown(trustedPort)))

	// Every critical section below is CN-scoped: a global lock would
	// serialize unrelated users behind a reconnect storm.
	lockPath := filepath.Join(cfg.SessionsDir, ".lock."+safeCN)
	var exit int
	if err := store.Lock(lockPath, func() error {
		exit = connectLocked(cfg, cn, safeCN, trustedIP, trustedPort, poolIP, key, limit)
		return nil
	}); err != nil {
		// Without the lock two sessions of the same user could pass the
		// limit check at once. Refuse rather than guess.
		logging.Event(cfg.LogFile, "CN=%s could not take the session lock: %v; REJECT", cn, err)
		return 1
	}
	return exit
}

// connectLocked is the policy under the per-CN lock.
func connectLocked(
	cfg config.Hook,
	cn, safeCN, trustedIP, trustedPort, poolIP, key string,
	limit int,
) int {
	// One status read for the whole hook: the live session count of this
	// CN decides admission.
	sessions := liveRows(ovpn.SessionsForCN(cfg.StatusFile, cn))
	count := len(sessions)

	if count >= limit {
		if limit != 1 {
			logging.Event(cfg.LogFile, "CN=%s ip=%s:%s pool=%s limit=%d status=%d; REJECT",
				cn, orUnknown(trustedIP), orUnknown(trustedPort), orNone(poolIP), limit, count)
			return 1
		}
		if !takeover(cfg, cn, safeCN, trustedIP, trustedPort, poolIP, sessions, count) {
			return 1
		}
	}

	if limit == 1 {
		// One session per user: the new marker replaces the old ones.
		store.RemoveMarkers(cfg.SessionsDir, safeCN)
	}

	marker := store.Marker{
		CommonName:  cn,
		TrustedIP:   trustedIP,
		TrustedPort: trustedPort,
		PoolIP:      poolIP,
		Created:     time.Now().Unix(),
	}
	if err := store.WriteMarker(filepath.Join(cfg.SessionsDir, key), marker); err != nil {
		logging.Event(cfg.LogFile, "CN=%s could not write the session marker: %v; REJECT", cn, err)
		return 1
	}

	logging.Event(cfg.LogFile, "CN=%s ip=%s:%s pool=%s limit=%d status=%d; ALLOW session=%s",
		cn, orUnknown(trustedIP), orUnknown(trustedPort), orNone(poolIP), limit, count, key)
	return 0
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
	var cids []string
	for _, s := range sessions {
		if isDigits(s.ClientID) {
			cids = append(cids, s.ClientID)
		}
	}
	logging.Event(cfg.LogFile,
		"CN=%s ip=%s:%s pool=%s limit=1 status=%d; TAKEOVER (%d mgmt cmds, one session)",
		cn, orUnknown(trustedIP), orUnknown(trustedPort), orNone(poolIP), count, len(cids))

	// The sidecar is written BEFORE the attempt: the panel toasts the
	// displaced user on their next login, and a takeover that failed still
	// displaced somebody.
	sidecar := writeLastKill(cfg.UsersDir, safeCN, time.Now().Unix())
	logging.Event(cfg.LogFile, "CN=%s wrote kill sidecar=%s", cn, sidecar)

	result, lines := ovpn.Takeover(cfg.MgmtHost, cfg.MgmtPort, cfg.MgmtPassFile, cn, cids)
	for _, line := range lines {
		logging.Event(cfg.LogFile, "CN=%s mgmt: %s", cn, line)
	}

	switch result {
	case ovpn.TakeoverVerified:
		store.RemoveMarkers(cfg.SessionsDir, safeCN)
		return true
	case ovpn.TakeoverTimeout:
		logging.Event(cfg.LogFile,
			"CN=%s ip=%s:%s pool=%s takeover could not verify old session termination; REJECT",
			cn, orUnknown(trustedIP), orUnknown(trustedPort), orNone(poolIP))
		return false
	default:
		logging.Event(cfg.LogFile,
			"CN=%s ip=%s:%s pool=%s limit=1 status=%d; management unavailable; DEGRADE (markers replaced, corpse reaped by ping-restart)",
			cn, orUnknown(trustedIP), orUnknown(trustedPort), orNone(poolIP), count)
		store.RemoveMarkers(cfg.SessionsDir, safeCN)
		return true
	}
}

// writeLastKill writes the kill-reason sidecar the panel reads to toast the
// displaced user. It returns the path it wrote.
func writeLastKill(usersDir, safeCN string, at int64) string {
	dir := filepath.Join(usersDir, safeCN)
	_ = os.MkdirAll(dir, 0o755)
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
		if s.VirtualAddress == "" && s.ClientID == "" && s.RealAddress == "" {
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
