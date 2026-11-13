// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"errors"
	"testing"
	"time"

	"ovnode/internal/ovpn"
)

func withReaper(t *testing.T, sessions []ovpn.Session, limit int) (*[]string, func()) {
	t.Helper()
	prevSessions, prevKill, prevLimit := reapSessions, reapKill, reapLimit
	var killed []string
	reapSessions = func() []ovpn.Session { return sessions }
	reapLimit = func(string) int { return limit }
	reapKill = func(cn string) error { killed = append(killed, cn); return nil }
	return &killed, func() { reapSessions, reapKill, reapLimit = prevSessions, prevKill, prevLimit }
}

// All rows are failed connections (zero tun bytes): safe to drop the whole CN.
func TestReapAllZeroByteOverflowAfterGrace(t *testing.T) {
	now := time.Now()
	sessions := []ovpn.Session{
		{CommonName: "u1", TrustedIP: "1.1.1.1", TrustedPort: "100", ClientID: "11", ConnectedAt: now.Add(-2 * time.Minute).Unix()},
		{CommonName: "u1", TrustedIP: "2.2.2.2", TrustedPort: "200", ClientID: "12", ConnectedAt: now.Add(-90 * time.Second).Unix()},
		{CommonName: "u1", TrustedIP: "3.3.3.3", TrustedPort: "300", ClientID: "13", ConnectedAt: now.Add(-30 * time.Second).Unix()},
	}
	killed, restore := withReaper(t, sessions, 2)
	defer restore()
	seen := map[string]time.Time{}

	if got := reapOnce(now, OverflowGrace, seen); len(got) != 0 {
		t.Fatalf("killed before the grace: %v", got)
	}
	got := reapOnce(now.Add(OverflowGrace+time.Second), OverflowGrace, seen)
	if len(got) != 1 || got[0] != "u1" {
		t.Fatalf("killed %v, want the whole CN u1", got)
	}
	if len(*killed) != 1 {
		t.Fatalf("kill calls = %v", *killed)
	}
}

// Several real devices behind one NAT share an address; they must never be
// treated as copies and killed together.
func TestReapLeavesSameIPDevices(t *testing.T) {
	now := time.Now()
	sessions := []ovpn.Session{
		{CommonName: "u2", TrustedIP: "5.5.5.5", TrustedPort: "100", ClientID: "21", ConnectedAt: now.Add(-2 * time.Minute).Unix(), BytesReceived: 10},
		{CommonName: "u2", TrustedIP: "5.5.5.5", TrustedPort: "101", ClientID: "22", ConnectedAt: now.Add(-60 * time.Second).Unix(), BytesReceived: 10},
		{CommonName: "u2", TrustedIP: "5.5.5.5", TrustedPort: "102", ClientID: "23", ConnectedAt: now.Add(-10 * time.Second).Unix(), BytesReceived: 10},
	}
	killed, restore := withReaper(t, sessions, 2)
	defer restore()
	seen := map[string]time.Time{}
	reapOnce(now, OverflowGrace, seen)
	got := reapOnce(now.Add(OverflowGrace+time.Second), OverflowGrace, seen)
	if len(got) != 0 || len(*killed) != 0 {
		t.Fatalf("kicked same-NAT devices: %v", *killed)
	}
}

// A live second device on another IP must never be kicked.
func TestReapLeavesMixedOverflow(t *testing.T) {
	now := time.Now()
	sessions := []ovpn.Session{
		{CommonName: "u3", TrustedIP: "1.1.1.1", TrustedPort: "100", ClientID: "31", ConnectedAt: now.Add(-2 * time.Minute).Unix(), BytesReceived: 5},
		{CommonName: "u3", TrustedIP: "1.1.1.1", TrustedPort: "101", ClientID: "32", ConnectedAt: now.Add(-time.Minute).Unix(), BytesReceived: 5},
		{CommonName: "u3", TrustedIP: "2.2.2.2", TrustedPort: "200", ClientID: "33", ConnectedAt: now.Add(-30 * time.Second).Unix(), BytesSent: 6},
	}
	killed, restore := withReaper(t, sessions, 2)
	defer restore()
	seen := map[string]time.Time{}
	reapOnce(now, OverflowGrace, seen)
	reapOnce(now.Add(OverflowGrace+time.Second), OverflowGrace, seen)
	if len(*killed) != 0 {
		t.Fatalf("kicked a mixed live set: %v", *killed)
	}
}

func TestReapUnlimitedAndAtLimitDoNothing(t *testing.T) {
	now := time.Now()
	sessions := []ovpn.Session{
		{CommonName: "u4", TrustedIP: "1.1.1.1", TrustedPort: "100", ClientID: "41", ConnectedAt: now.Add(-time.Minute).Unix()},
		{CommonName: "u4", TrustedIP: "2.2.2.2", TrustedPort: "200", ClientID: "42", ConnectedAt: now.Add(-time.Minute).Unix()},
	}
	killed, restore := withReaper(t, sessions, 0) // unlimited
	defer restore()
	seen := map[string]time.Time{}
	reapOnce(now, OverflowGrace, seen)
	reapOnce(now.Add(OverflowGrace+time.Second), OverflowGrace, seen)
	if len(*killed) != 0 {
		t.Fatalf("unlimited user had a session kicked: %v", *killed)
	}

	killed, restore2 := withReaper(t, sessions, 2) // exactly at the limit
	defer restore2()
	reapOnce(now, OverflowGrace, seen)
	reapOnce(now.Add(OverflowGrace+time.Second), OverflowGrace, seen)
	if len(*killed) != 0 {
		t.Fatalf("at-limit user had a session kicked: %v", *killed)
	}
}

// A failed kill is retried on the next tick, not forgotten.
func TestReapRetriesFailedKill(t *testing.T) {
	now := time.Now()
	sessions := []ovpn.Session{
		{CommonName: "u5", TrustedIP: "1.1.1.1", TrustedPort: "100", ClientID: "51", ConnectedAt: now.Add(-2 * time.Minute).Unix()},
		{CommonName: "u5", TrustedIP: "2.2.2.2", TrustedPort: "200", ClientID: "52", ConnectedAt: now.Add(-2 * time.Minute).Unix()},
	}
	killed, restore := withReaper(t, sessions, 1)
	defer restore()
	var calls int
	reapKill = func(cn string) error {
		calls++
		if calls == 1 {
			return errors.New("management down")
		}
		*killed = append(*killed, cn)
		return nil
	}
	seen := map[string]time.Time{}
	reapOnce(now, OverflowGrace, seen)
	reapOnce(now.Add(OverflowGrace+time.Second), OverflowGrace, seen) // fails
	if len(*killed) != 0 {
		t.Fatalf("kill reported success while failing")
	}
	reapOnce(now.Add(OverflowGrace+3*time.Second), OverflowGrace, seen)
	if len(*killed) != 1 {
		t.Fatalf("retry did not kill: %v", *killed)
	}
}
