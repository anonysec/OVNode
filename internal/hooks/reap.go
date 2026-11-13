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
	"ovnode/internal/store"
)

// ReapOverflow reclaims the +1 overflow reserve in the background.
//
// Under DCO the only working management kill is "kill <cn>", which removes
// every session of the user. So a reclaim happens only when every row is a
// zero-byte failed connection — safe to lose. Anything with real usage (a live
// device, several devices behind one NAT) is left alone and drains at
// keepalive; the next connect then decides at the hard cap.
func ReapOverflow(ctx context.Context, interval, grace time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	seen := map[string]time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			reapOnce(now, grace, seen)
		}
	}
}

var (
	reapSessions = ovpn.AllSessions
	reapKill     = killUserForReaper
	reapLimit    = userLimit
)

// reapOnce evaluates every CN once. seen tracks when an overflow was first
// observed, so the grace applies to the overflow rather than to one session.
func reapOnce(now time.Time, grace time.Duration, seen map[string]time.Time) []string {
	byCN := map[string][]ovpn.Session{}
	for _, s := range reapSessions() {
		if s.CommonName != "" {
			byCN[s.CommonName] = append(byCN[s.CommonName], s)
		}
	}
	var killed []string
	for cn, list := range byCN {
		limit := reapLimit(cn)
		if limit <= 0 || len(list) <= limit {
			delete(seen, cn)
			continue
		}
		first, ok := seen[cn]
		if !ok {
			seen[cn] = now
			continue
		}
		if now.Sub(first) < grace {
			continue
		}
		if !overflowAllKillable(list) {
			continue // a live device is present: soft overflow, never kick it
		}
		if err := reapKill(cn); err != nil {
			logging.Event(fsx.LogFile(), "CN=%s limit=%d count=%d; overflow reclaim failed: %v",
				cn, limit, len(list), err)
			continue
		}
		logging.Event(fsx.LogFile(), "CN=%s limit=%d count=%d; overflow reaped (all rows reclaimable)",
			cn, limit, len(list))
		killed = append(killed, cn)
		delete(seen, cn)
	}
	return killed
}

// killUserForReaper kills every session of the CN across the management
// sockets; any SUCCESS reply confirms the command was accepted.
func killUserForReaper(cn string) error {
	replies, err := ovpn.SendCommands([]string{"kill " + cn})
	if err != nil {
		return err
	}
	for _, reply := range replies {
		if strings.Contains(strings.ToUpper(reply), "SUCCESS") {
			return nil
		}
	}
	return fmt.Errorf("management did not confirm the kill")
}

// userLimit resolves a CN's configured session limit.
func userLimit(cn string) int {
	state, err := store.ReadUserState(fsx.UsersDir(), cn)
	if err != nil || !state.LimitSet {
		return config.DefaultLimit
	}
	return state.Limit
}
