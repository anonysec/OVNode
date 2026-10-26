// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"ovnode/internal/pki"
	"ovnode/internal/store"
)

// UsersUsage returns the per-user traffic counters in the shape the panel
// consumes.
//
// Two panel consumers of GET /sync/usage:
//
//  1. the traffic collector resolves the "users" keys by USERNAME, so the
//     keys are the display names where they are known
//  2. the global mlogin registry resolves the "sessions" keys by the
//     numeric common name, so "sessions" carries the common name too
//
// "totals" is additive: the banked bytes of the finished sessions plus the
// bytes of the live ones.
func UsersUsage() map[string]any {
	sessions := ParseSessions(StatusFile())
	users := map[string]uint64{}
	perSession := map[string]map[string]uint64{}
	for _, s := range sessions {
		total := s.BytesReceived + s.BytesSent
		users[s.CommonName] += total
		if perSession[s.CommonName] == nil {
			perSession[s.CommonName] = map[string]uint64{}
		}
		perSession[s.CommonName][s.RealAddress] = total
	}

	names := store.NameMap(pki.UsersDir())
	display := func(cn string) string {
		if name := names[cn]; name != "" {
			return name
		}
		return cn
	}

	liveByName := map[string]uint64{}
	for cn, total := range users {
		liveByName[display(cn)] += total
	}
	sessionRows := map[string]map[string]uint64{}
	for cn, per := range perSession {
		sessionRows[cn] = per
		if name := names[cn]; name != "" && name != cn {
			sessionRows[name] = per
		}
	}

	totals := map[string]uint64{}
	for cn, banked := range store.AllAccumulatedUsage(pki.UsageDir()) {
		totals[display(cn)] += banked
	}
	for key, live := range liveByName {
		totals[key] += live
	}

	return map[string]any{
		"users":    liveByName,
		"sessions": sessionRows,
		"totals":   totals,
	}
}
