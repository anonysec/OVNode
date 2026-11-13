// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"errors"
	"testing"
	"time"

	"ovnode/internal/ovpn"
	"ovnode/internal/settings"
)

func newReapState() *reapState {
	return &reapState{first: map[string]time.Time{}, last: map[string]time.Time{}}
}

func withReaper(t *testing.T, sessions []ovpn.Session, limit int, policy settings.LimitPolicy) *[]string {
	t.Helper()
	prevSessions, prevKill, prevLimit, prevPolicy := reapSessions, reapKill, reapLimit, reapPolicy
	var killed []string
	reapSessions = func() []ovpn.Session { return sessions }
	reapLimit = func(string) int { return limit }
	reapKill = func(cid, proto string) error { killed = append(killed, cid); return nil }
	reapPolicy = func() (settings.LimitPolicy, error) { return policy, nil }
	t.Cleanup(func() {
		reapSessions, reapKill, reapLimit, reapPolicy = prevSessions, prevKill, prevLimit, prevPolicy
	})
	return &killed
}

func overflowRows() []ovpn.Session {
	return []ovpn.Session{
		{CommonName: "u1", TrustedIP: "1.1.1.1", TrustedPort: "100", ClientID: "41", ConnectedAt: 100, BytesReceived: 10},
		{CommonName: "u1", TrustedIP: "2.2.2.2", TrustedPort: "200", ClientID: "42", ConnectedAt: 200, BytesReceived: 10},
		{CommonName: "u1", TrustedIP: "3.3.3.3", TrustedPort: "300", ClientID: "43", ConnectedAt: 300, BytesReceived: 10},
	}
}

// A persistent third live session is killed only after the grace, and only by
// its numeric client id.
func TestReapReserveKillsNewestAfterGrace(t *testing.T) {
	killed := withReaper(t, overflowRows(), 2, settings.LimitReserve)
	now := time.Now()
	state := newReapState()

	if got := reapOnce(now, 150*time.Second, state); len(got) != 0 {
		t.Fatalf("killed before the grace: %v", got)
	}
	if got := reapOnce(now.Add(149*time.Second), 150*time.Second, state); len(got) != 0 {
		t.Fatalf("killed inside the grace: %v", got)
	}
	got := reapOnce(now.Add(151*time.Second), 150*time.Second, state)
	if len(got) != 1 || got[0] != "43" {
		t.Fatalf("killed %v, want the newest client id 43", got)
	}
	if len(*killed) != 1 {
		t.Fatalf("kill calls = %v", *killed)
	}
	if !isDigits((*killed)[0]) {
		t.Fatalf("targeted kill used %q, want a numeric client id", (*killed)[0])
	}
}

// When the stale row from the reconnect expires first, the healthy reconnect
// survives and the reaper does nothing.
func TestReapReserveKeepsReconnectAfterStaleRowExpires(t *testing.T) {
	sessions := overflowRows()
	withReaper(t, sessions, 2, settings.LimitReserve)
	now := time.Now()
	state := newReapState()

	if got := reapOnce(now, 150*time.Second, state); len(got) != 0 {
		t.Fatalf("killed at first observation: %v", got)
	}
	// The old row 41 expired; the reconnect 43 is now one of exactly two.
	reapSessions = func() []ovpn.Session { return sessions[1:] }
	if got := reapOnce(now.Add(151*time.Second), 150*time.Second, state); len(got) != 0 {
		t.Fatalf("killed the healthy reconnect: %v", got)
	}
}

func TestReapReserveDoesNothingForOtherPolicies(t *testing.T) {
	for _, policy := range []settings.LimitPolicy{settings.LimitStrict, settings.LimitTakeover} {
		t.Run(string(policy), func(t *testing.T) {
			killed := withReaper(t, overflowRows(), 2, policy)
			now := time.Now()
			state := newReapState()
			reapOnce(now, 150*time.Second, state)
			if got := reapOnce(now.Add(301*time.Second), 150*time.Second, state); len(got) != 0 {
				t.Fatalf("policy %q reaped: %v", policy, got)
			}
			if len(*killed) != 0 {
				t.Fatalf("policy %q kill calls = %v", policy, *killed)
			}
		})
	}
}

func TestReapReserveSkipsLimitOne(t *testing.T) {
	killed := withReaper(t, overflowRows()[:2], 1, settings.LimitReserve)
	now := time.Now()
	state := newReapState()
	reapOnce(now, 150*time.Second, state)
	if got := reapOnce(now.Add(301*time.Second), 150*time.Second, state); len(got) != 0 {
		t.Fatalf("limit=1 reaped: %v", got)
	}
	if len(*killed) != 0 {
		t.Fatalf("limit=1 kill calls = %v", *killed)
	}
}

// A failed kill is retried after the retry interval, not on every tick.
func TestReapReserveRetriesFailedKill(t *testing.T) {
	killed := withReaper(t, overflowRows(), 2, settings.LimitReserve)
	var calls int
	reapKill = func(cid, proto string) error {
		calls++
		if calls == 1 {
			return errors.New("management down")
		}
		*killed = append(*killed, cid)
		return nil
	}
	now := time.Now()
	state := newReapState()
	reapOnce(now, 150*time.Second, state)
	if got := reapOnce(now.Add(151*time.Second), 150*time.Second, state); len(got) != 0 {
		t.Fatalf("failed kill reported success: %v", got)
	}
	if len(*killed) != 0 {
		t.Fatalf("failed kill recorded: %v", *killed)
	}
	if got := reapOnce(now.Add(151*time.Second+31*time.Second), 150*time.Second, state); len(got) != 1 || got[0] != "43" {
		t.Fatalf("retry did not kill 43: %v", got)
	}
}
