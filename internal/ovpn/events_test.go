// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestClassifyReject covers the severity table of the hook lines.
//
// A reject is not automatically an authentication failure: the panel used to
// present a disabled user's reconnect as a security incident, so the
// classification decides what the operator sees.
func TestClassifyReject(t *testing.T) {
	cases := []struct {
		name     string
		message  string
		action   string
		severity string
		reason   string
	}{
		{
			name:     "disabled user",
			message:  "CN=7 ip=1.2.3.4:5678 is disabled; REJECT",
			action:   "disabled",
			severity: SeverityPolicy,
			reason:   "user disabled in the panel",
		},
		{
			name:     "missing user tree",
			message:  "CN=7 ip=1.2.3.4:5678; USERS_DIR missing or not a directory — fail-closed; REJECT",
			action:   "fail_closed",
			severity: SeverityFailure,
			reason:   "node user state missing",
		},
		{
			name:     "takeover not verified",
			message:  "CN=7 ip=1.2.3.4:5678 pool=10.8.0.2 limit=1 status=1; takeover could not verify old session termination; REJECT",
			action:   "takeover_failed",
			severity: SeverityFailure,
			reason:   "old session not terminated",
		},
		{
			name:     "management down",
			message:  "CN=7 ip=1.2.3.4:5678 pool=10.8.0.2 limit=1 status=1; management unavailable; DEGRADE",
			action:   "mgmt_degraded",
			severity: SeverityWarn,
			reason:   "management unavailable",
		},
		{
			name:     "panel refused",
			message:  "CN=7 ip=1.2.3.4:5678 GLOBAL_REJECT policy=quota",
			action:   "global_policy",
			severity: SeverityPolicy,
			reason:   "panel rejected the connection",
		},
		{
			name:     "max logins reached",
			message:  "CN=7 ip=1.2.3.4:5678 pool=10.8.0.2 limit=2 status=2; REJECT",
			action:   "max_logins",
			severity: SeverityPolicy,
			reason:   "max logins reached",
		},
		{
			name:     "unexplained reject",
			message:  "CN=7 ip=1.2.3.4:5678 something odd; REJECT",
			action:   "other",
			severity: SeverityWarn,
			reason:   "unclassified reject",
		},
		{
			name:     "policy check failed",
			message:  "CN=7 ip=1.2.3.4:5678 policy check FAILED",
			action:   "check_failed",
			severity: SeverityWarn,
			reason:   "policy check failed",
		},
		{
			name:     "admitted session",
			message:  "CN=7 ip=1.2.3.4:5678 pool=10.8.0.2 limit=1 status=0; ALLOW session=7.10.8.0.2",
			action:   "event",
			severity: SeverityPolicy,
			reason:   "session event",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			action, severity, reason := classifyReject(c.message)
			if action != c.action || severity != c.severity || reason != c.reason {
				t.Fatalf("classify(%q) = %q/%q/%q, want %q/%q/%q",
					c.message, action, severity, reason, c.action, c.severity, c.reason)
			}
		})
	}
}

// TestHookEventLogIsRead covers the event log parsing: the file is the
// node's own record of what the hook decided.
func TestHookEventLogIsRead(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_LOG_FILE", dir+"/hook-events.log")
	// A line inside the window, one outside it and one that is not a
	// timestamp at all.
	now := time.Now().Unix()
	body := fmt.Sprintf("%d [ovnode-mlogin] CN=7 ip=1.2.3.4:5678; USERS_DIR missing; REJECT\n", now) +
		"1 [ovnode-mlogin] CN=8 ip=1.2.3.4:5679 is disabled; REJECT\n" +
		"not-a-timestamp [ovnode-mlogin] CN=9 ignored\n"
	if err := os.WriteFile(dir+"/hook-events.log", []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	events := readHookEvents(8)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1 (only the line inside the window)", len(events))
	}
	if int64(events[0].ts) != now {
		t.Fatalf("ts = %v, want %d", events[0].ts, now)
	}
	if !strings.Contains(events[0].message, "USERS_DIR missing") {
		t.Fatalf("message = %q, want the hook line", events[0].message)
	}
}

// TestClampHours covers the event window: a client-controlled window must
// not ask for a week of history.
func TestClampHours(t *testing.T) {
	cases := map[int]int{0: 1, -5: 1, 8: 8, 168: 24}
	for in, want := range cases {
		if got := clampHours(in); got != want {
			t.Errorf("clampHours(%d) = %d, want %d", in, got, want)
		}
	}
}
