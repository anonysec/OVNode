// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"os"
	"testing"
	"time"

	"ovnode/internal/store"
)

// writeOneSessionStatus writes one unchanged status fixture: the file
// OpenVPN rewrites only every 5 seconds, so two connects inside the window
// see the same stale list.
func writeOneSessionStatus(t *testing.T, tr *tree, cn, pool, real, cid string) {
	t.Helper()
	status := "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID\n" +
		"CLIENT_LIST," + cn + "," + real + "," + pool + ",,,,0,0,,,," + cid + ",0\n"
	if err := os.WriteFile(tr.status, []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
}

func connectAs(t *testing.T, tr *tree, cn, pool string) int {
	t.Helper()
	setClientEnv(t, cn, pool)
	return Connect(tr.config(), "")
}

// TestStaleStatusAllowsMoreThanLimit reproduces the stale-status hole: the
// fixture is never rewritten between connects, so every call sees one old
// session and the marker count must stop the excess after the fix.
func TestStaleStatusAllowsMoreThanLimit(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=0\n")
	writeOneSessionStatus(t, tr, "u1", "10.8.0.2", "9.9.9.9:5001", "1")
	first := connectAs(t, tr, "u1", "10.8.0.11")
	second := connectAs(t, tr, "u1", "10.8.0.12")
	// The stale file still lists one session at limit=1, so takeover must
	// fire. Management is pointed at a dead port here, and the first
	// connect left a fresh marker: the second must be refused.
	if first != 0 || second != 1 {
		t.Fatalf("limit=1 codes = %d, %d; want 0, 1 (stale list admits too many)", first, second)
	}

	tr2 := newTree(t)
	tr2.user(t, "u1", "limit=2\ndisabled=0\n")
	writeOneSessionStatus(t, tr2, "u1", "10.8.0.2", "9.9.9.9:5001", "1")
	got := []int{
		connectAs(t, tr2, "u1", "10.8.0.11"),
		connectAs(t, tr2, "u1", "10.8.0.12"),
		connectAs(t, tr2, "u1", "10.8.0.13"),
	}
	// One stale session plus two fresh markers reaches the limit of 2; the
	// third connect must be refused.
	want := []int{0, 0, 1}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("limit=2 codes = %v; want %v (stale list admits too many)", got, want)
		}
	}
}

// TestFreshTakeoverMarkerRejectsWhenManagementDown covers the limit=1,
// management-down path: a fresh old-session marker means the displaced
// session is still live and must not be replaced blindly.
func TestFreshTakeoverMarkerRejectsWhenManagementDown(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=0\n")
	writeOneSessionStatus(t, tr, "u1", "10.8.0.2", "9.9.9.9:5001", "1")
	if err := store.WriteMarker(tr.sessions+"/u1.10.8.0.2", store.Marker{
		CommonName:  "u1",
		TrustedIP:   "9.9.9.9",
		TrustedPort: "5001",
		PoolIP:      "10.8.0.2",
		Created:     time.Now().Unix(),
		SessionID:   "u1.10.8.0.2.gen",
		ConnectedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if code := connectAs(t, tr, "u1", "10.8.0.11"); code != 1 {
		t.Fatalf("Connect with fresh marker and dead management = %d, want 1", code)
	}
	found := false
	for _, e := range tr.events(t) {
		if contains(e, "could not verify") && contains(e, "REJECT") {
			found = true
		}
	}
	if !found {
		t.Fatalf("events = %q; want a could-not-verify REJECT line", tr.events(t))
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
