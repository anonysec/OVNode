// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"errors"
	"os"
	"strings"
	"testing"

	"ovnode/internal/settings"
)

const overflowHeader = "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID\n"

func writeOverflowStatus(t *testing.T, tr *tree, rows ...string) {
	t.Helper()
	body := overflowHeader + strings.Join(rows, "\n") + "\n"
	if err := os.WriteFile(tr.status, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// LiveSessionsForCN reads every protocol's status file; point all of them
	// at this fixture (the process env is consulted when .env has no key).
	t.Setenv("StatusFile", tr.status)
}

func row(cn, real, virtual, recv, sent, cid string) string {
	return "CLIENT_LIST," + cn + "," + real + "," + virtual + ",," + recv + "," + sent +
		",2026-01-01 00:00:00,1767225600,," + cid + ",0"
}

func hasEvent(events []string, substr string) bool {
	for _, line := range events {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

func withPolicy(t *testing.T, policy settings.LimitPolicy) {
	t.Helper()
	prev := loadLimitPolicy
	loadLimitPolicy = func() (settings.LimitPolicy, error) { return policy, nil }
	t.Cleanup(func() { loadLimitPolicy = prev })
}

func withKill(t *testing.T) *[]string {
	t.Helper()
	prev := notifyKill
	var commands []string
	notifyKill = func(cid, proto string) error {
		commands = append(commands, "client-kill "+cid)
		return nil
	}
	t.Cleanup(func() { notifyKill = prev })
	return &commands
}

func withKillError(t *testing.T) {
	t.Helper()
	prev := notifyKill
	notifyKill = func(string, string) error { return errors.New("agent socket down") }
	t.Cleanup(func() { notifyKill = prev })
}

// Strict refuses the third connection of a limit-2 user.
func TestConnectStrictRejectsAtLimit(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=2\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "1.1.1.1:1000", "10.8.0.3", "100", "200", "41"),
		row("u1", "2.2.2.2:2000", "10.8.0.4", "100", "200", "42"),
	)
	setClientEnv(t, "u1", "10.8.0.2")
	withPolicy(t, settings.LimitStrict)

	if code := Connect(tr.config(), ""); code != 1 {
		t.Fatalf("Connect = %d, want 1", code)
	}
	if !hasEvent(tr.events(t), "REJECT (strict)") {
		t.Fatalf("strict refusal not logged: %v", tr.events(t))
	}
}

// Reserve admits the reconnect as one temporary extra session.
func TestConnectReserveAllowsThirdSession(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=2\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "1.1.1.1:1000", "10.8.0.3", "100", "200", "41"),
		row("u1", "2.2.2.2:2000", "10.8.0.4", "100", "200", "42"),
	)
	setClientEnv(t, "u1", "10.8.0.2")
	withPolicy(t, settings.LimitReserve)

	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect = %d, want 0 (reserve)", code)
	}
	if !hasEvent(tr.events(t), "ALLOW (overflow reserve +1)") {
		t.Fatalf("reserve admission not logged: %v", tr.events(t))
	}
}

// A fourth live connection is refused.
func TestConnectReserveRefusesFourthLive(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=2\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "1.1.1.1:1000", "10.8.0.3", "100", "200", "41"),
		row("u1", "2.2.2.2:2000", "10.8.0.4", "100", "200", "42"),
		row("u1", "3.3.3.3:3000", "10.8.0.5", "100", "200", "43"),
	)
	setClientEnv(t, "u1", "10.8.0.2")
	withPolicy(t, settings.LimitReserve)
	commands := withKill(t)

	if code := Connect(tr.config(), ""); code != 1 {
		t.Fatalf("Connect = %d, want 1", code)
	}
	if len(*commands) != 0 {
		t.Fatalf("live rows were killed: %v", *commands)
	}
	if !hasEvent(tr.events(t), "REJECT (overflow cap)") {
		t.Fatalf("overflow refusal not logged: %v", tr.events(t))
	}
}

// A zero-byte newest row is reclaimed, but the fourth connection is still
// refused so N+2 is never admitted.
func TestConnectReserveReclaimsZeroByteNewest(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=2\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "1.1.1.1:1000", "10.8.0.3", "100", "200", "41"),
		row("u1", "2.2.2.2:2000", "10.8.0.4", "100", "200", "42"),
		row("u1", "3.3.3.3:3000", "10.8.0.5", "0", "0", "43"),
	)
	setClientEnv(t, "u1", "10.8.0.2")
	withPolicy(t, settings.LimitReserve)
	commands := withKill(t)

	if code := Connect(tr.config(), ""); code != 1 {
		t.Fatalf("Connect = %d, want 1", code)
	}
	if len(*commands) != 1 || (*commands)[0] != "client-kill 43" {
		t.Fatalf("commands = %v, want client-kill 43", *commands)
	}
	if !hasEvent(tr.events(t), "RECLAIM queued client-kill cid=43") {
		t.Fatalf("reclaim not logged: %v", tr.events(t))
	}
}

// Takeover prefers the reconnecting device's own network, then newest.
func TestConnectTakeoverReplacesSameIP(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=2\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "9.9.9.9:5002", "10.8.0.3", "100", "200", "41"),
		row("u1", "9.9.9.9:5003", "10.8.0.4", "100", "200", "42"),
	)
	setClientEnv(t, "u1", "10.8.0.2")
	withPolicy(t, settings.LimitTakeover)
	commands := withKill(t)

	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect = %d, want 0 (takeover)", code)
	}
	if len(*commands) != 1 || (*commands)[0] != "client-kill 42" {
		t.Fatalf("commands = %v, want the newest same-IP session 42", *commands)
	}
	if !hasEvent(tr.events(t), "TAKEOVER queued client-kill cid=42") {
		t.Fatalf("takeover not logged: %v", tr.events(t))
	}
}

// With no matching network, takeover replaces the newest existing session.
func TestConnectTakeoverFallsBackToNewest(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=2\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "1.1.1.1:1000", "10.8.0.3", "100", "200", "41"),
		row("u1", "2.2.2.2:2000", "10.8.0.4", "100", "200", "42"),
	)
	setClientEnv(t, "u1", "10.8.0.2")
	withPolicy(t, settings.LimitTakeover)
	commands := withKill(t)

	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect = %d, want 0 (takeover)", code)
	}
	if len(*commands) != 1 || (*commands)[0] != "client-kill 42" {
		t.Fatalf("commands = %v, want the newest session 42", *commands)
	}
}

func TestConnectTakeoverQueueFailureDegrades(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=2\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "1.1.1.1:1000", "10.8.0.3", "100", "200", "41"),
		row("u1", "2.2.2.2:2000", "10.8.0.4", "100", "200", "42"),
	)
	setClientEnv(t, "u1", "10.8.0.2")
	withPolicy(t, settings.LimitTakeover)
	withKillError(t)

	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect = %d, want 0 (degrade)", code)
	}
	if !hasEvent(tr.events(t), "DEGRADE (takeover, queue failed") {
		t.Fatalf("takeover degrade not logged: %v", tr.events(t))
	}
}

func TestConnectTakeoverAtCapRejects(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=2\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "1.1.1.1:1000", "10.8.0.3", "100", "200", "41"),
		row("u1", "2.2.2.2:2000", "10.8.0.4", "100", "200", "42"),
		row("u1", "3.3.3.3:3000", "10.8.0.5", "100", "200", "43"),
	)
	setClientEnv(t, "u1", "10.8.0.2")
	withPolicy(t, settings.LimitTakeover)
	commands := withKill(t)

	if code := Connect(tr.config(), ""); code != 1 {
		t.Fatalf("Connect = %d, want 1", code)
	}
	if len(*commands) != 0 {
		t.Fatalf("takeover acted at the cap: %v", *commands)
	}
	if !hasEvent(tr.events(t), "REJECT (takeover cap)") {
		t.Fatalf("takeover cap not logged: %v", tr.events(t))
	}
}

// Unlimited ignores the policy entirely.
func TestConnectUnlimitedIgnoresPolicy(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=0\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "1.1.1.1:1000", "10.8.0.3", "100", "200", "41"),
		row("u1", "2.2.2.2:2000", "10.8.0.4", "100", "200", "42"),
		row("u1", "3.3.3.3:3000", "10.8.0.5", "100", "200", "43"),
	)
	setClientEnv(t, "u1", "10.8.0.2")
	withPolicy(t, settings.LimitStrict)

	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect = %d, want 0 (unlimited)", code)
	}
}
