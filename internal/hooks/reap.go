// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ovnode/internal/config"
	"ovnode/internal/fsx"
	"ovnode/internal/logging"
	"ovnode/internal/ovpn"
	"ovnode/internal/settings"
	"ovnode/internal/store"
)

const (
	reapInterval = 2 * time.Second
	reapRetry    = 30 * time.Second
	reapGrace    = 150 * time.Second
)

// ReapOverflow turns the temporary reserve in reserve mode back into the
// configured limit. It targets only the newest session and never uses
// "kill <cn>": a stale row from a reconnect expires first, so a healthy
// reconnect survives; a persistent extra device is the one dropped.
func ReapOverflow(ctx context.Context) {
	ticker := time.NewTicker(reapInterval)
	defer ticker.Stop()
	state := &reapState{
		first: map[string]time.Time{},
		last:  map[string]time.Time{},
	}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			reapOnce(now, overflowGrace(), state)
		}
	}
}

// overflowGrace follows the node's dead-peer detection. A silently dropped
// session clears after roughly twice KeepaliveTimeout; the extra margin keeps
// a healthy reconnect from being mistaken for a real extra device.
func overflowGrace() time.Duration {
	cfg, err := settings.Load()
	if err != nil {
		return reapGrace
	}
	grace := time.Duration(2*cfg.KeepaliveTimeout+30) * time.Second
	if grace < 90*time.Second {
		grace = 90 * time.Second
	}
	return grace
}

type reapState struct {
	first map[string]time.Time
	last  map[string]time.Time
}

var (
	reapSessions = ovpn.AllSessions
	reapKill     = killSessionForReaper
	reapLimit    = userLimit
	reapPolicy   = settings.LoadLimitPolicy
)

// reapOnce evaluates every oversized CN once and returns the client ids it
// asked management to kill.
func reapOnce(now time.Time, grace time.Duration, state *reapState) []string {
	policy, err := reapPolicy()
	if err != nil {
		logging.Event(fsx.LogFile(), "limit policy: %v; using reserve", err)
	}
	if policy != settings.LimitReserve {
		state.first = map[string]time.Time{}
		state.last = map[string]time.Time{}
		return nil
	}

	byCN := map[string][]ovpn.Session{}
	for _, s := range reapSessions() {
		if s.CommonName != "" {
			byCN[s.CommonName] = append(byCN[s.CommonName], s)
		}
	}

	var killed []string
	for cn, list := range byCN {
		limit := reapLimit(cn)
		if limit <= 1 || len(list) <= limit {
			delete(state.first, cn)
			delete(state.last, cn)
			continue
		}
		first, ok := state.first[cn]
		if !ok {
			state.first[cn] = now
			continue
		}
		if now.Sub(first) < grace {
			continue
		}
		if last, ok := state.last[cn]; ok && now.Sub(last) < reapRetry {
			continue
		}
		target, ok := newestSession(list)
		if !ok {
			continue
		}
		if err := reapKill(target.ClientID); err != nil {
			logging.Event(fsx.LogFile(), "CN=%s limit=%d count=%d; overflow reclaim cid=%s failed: %v",
				cn, limit, len(list), target.ClientID, err)
			state.last[cn] = now
			continue
		}
		logging.Event(fsx.LogFile(), "CN=%s limit=%d count=%d; overflow reap client-kill cid=%s",
			cn, limit, len(list), target.ClientID)
		state.last[cn] = now
		killed = append(killed, target.ClientID)
	}

	for cn := range state.first {
		if _, ok := byCN[cn]; !ok {
			delete(state.first, cn)
			delete(state.last, cn)
		}
	}
	return killed
}

// killSessionForReaper sends one targeted client-kill. Any SUCCESS reply from
// a configured management socket confirms the command was accepted.
func killSessionForReaper(cid string) error {
	replies, err := ovpn.SendCommands([]string{"client-kill " + cid})
	if err != nil {
		return err
	}
	for _, reply := range replies {
		if strings.Contains(strings.ToUpper(reply), "SUCCESS") {
			return nil
		}
	}
	return fmt.Errorf("management did not confirm client-kill %s", cid)
}

// userLimit resolves a CN's configured session limit.
func userLimit(cn string) int {
	state, err := store.ReadUserState(fsx.UsersDir(), cn)
	if err != nil || !state.LimitSet {
		return config.DefaultLimit
	}
	return state.Limit
}
