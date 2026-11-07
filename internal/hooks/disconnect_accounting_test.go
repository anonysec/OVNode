// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"os"
	"path/filepath"
	"testing"

	"ovnode/internal/store"
)

func (tr *tree) usageTotal(t *testing.T, cn string) uint64 {
	t.Helper()
	st, err := store.ReadUsageState(tr.usage, cn)
	if err != nil {
		t.Fatal(err)
	}
	return st.Total
}

// TestConnectPersistsHookTimeUnix pins that the marker carries the actual
// hook connection start, not the hook run time.
func TestConnectPersistsHookTimeUnix(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=0\n")
	setClientEnv(t, "u1", "10.8.0.2")
	t.Setenv("time_unix", "1234567890")
	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect = %d, want 0", code)
	}
	m, ok := store.ReadMarker(filepath.Join(tr.sessions, "u1.10.8.0.2"))
	if !ok {
		t.Fatal("marker missing")
	}
	if m.ConnectionStarted != 1234567890 || m.ConnectedAt != 1234567890 {
		t.Fatalf("marker connection start = %d/%d, want 1234567890", m.ConnectionStarted, m.ConnectedAt)
	}
	if m.SessionID == "" {
		t.Fatal("marker has no generation session id")
	}
}

// TestDelayedDisconnectAfterPoolReuse: a delayed disconnect of generation 1
// must not bank into or delete generation 2's marker after pool reuse.
func TestDelayedDisconnectAfterPoolReuse(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=0\n")
	setClientEnv(t, "u1", "10.8.0.2")
	t.Setenv("time_unix", "1000")
	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("first Connect = %d, want 0", code)
	}
	// Pool IP reused by a new generation.
	setClientEnv(t, "u1", "10.8.0.2")
	t.Setenv("time_unix", "2000")
	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("second Connect = %d, want 0", code)
	}
	markerPath := filepath.Join(tr.sessions, "u1.10.8.0.2")
	gen2, ok := store.ReadMarker(markerPath)
	if !ok || gen2.ConnectionStarted != 2000 {
		t.Fatalf("new generation marker = %+v, want connection start 2000", gen2)
	}
	// Delayed disconnect of generation 1: must be ignored entirely.
	setClientEnv(t, "u1", "10.8.0.2")
	t.Setenv("time_unix", "1000")
	t.Setenv("bytes_received", "999")
	t.Setenv("bytes_sent", "0")
	if code := Disconnect(tr.config(), ""); code != 0 {
		t.Fatalf("delayed Disconnect = %d, want 0", code)
	}
	if got := tr.usageTotal(t, "u1"); got != 0 {
		t.Fatalf("delayed disconnect banked %d bytes into the new generation, want 0", got)
	}
	if m, ok := store.ReadMarker(markerPath); !ok || m.SessionID != gen2.SessionID {
		t.Fatal("delayed disconnect removed or replaced the new generation marker")
	}
	// The real generation-2 disconnect banks normally.
	t.Setenv("time_unix", "2000")
	t.Setenv("bytes_received", "30")
	t.Setenv("bytes_sent", "20")
	if code := Disconnect(tr.config(), ""); code != 0 {
		t.Fatalf("real Disconnect = %d, want 0", code)
	}
	if got := tr.usageTotal(t, "u1"); got != 50 {
		t.Fatalf("total=%d, want 50", got)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatal("real disconnect left the marker behind")
	}
}

// TestUnlimitedShortSessionIsBanked: limit=0 sessions still get accounting
// identity; a disconnect before any status poll banks all final bytes.
func TestUnlimitedShortSessionIsBanked(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=0\ndisabled=0\n")
	setClientEnv(t, "u1", "10.8.0.7")
	t.Setenv("time_unix", "3000")
	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect = %d, want 0", code)
	}
	if _, err := os.Stat(filepath.Join(tr.sessions, "u1.10.8.0.7")); err != nil {
		t.Fatalf("unlimited session has no accounting marker: %v", err)
	}
	t.Setenv("bytes_received", "77")
	t.Setenv("bytes_sent", "23")
	if code := Disconnect(tr.config(), ""); code != 0 {
		t.Fatalf("Disconnect = %d, want 0", code)
	}
	if got := tr.usageTotal(t, "u1"); got != 100 {
		t.Fatalf("total=%d, want 100", got)
	}
}

// TestDisconnectSameSecondTrustedReplacement: a new generation in the same
// second with a different trusted address must not be banked into or
// deleted by the old generation's delayed disconnect.
func TestDisconnectSameSecondTrustedReplacement(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=0\n")
	// New generation marker: v2 ID, start 5000, trusted 8.8.8.8.
	markerPath := filepath.Join(tr.sessions, "u1.10.8.0.2")
	if err := store.WriteMarker(markerPath, store.Marker{
		CommonName: "u1", PoolIP: "10.8.0.2", TrustedIP: "8.8.8.8", TrustedPort: "4000",
		Created: 5000, SessionID: "u1.10.8.0.2.1111111111111111", ConnectedAt: 5000,
	}); err != nil {
		t.Fatal(err)
	}
	// Old generation's delayed disconnect: same start second, trusted 9.9.9.9.
	setClientEnv(t, "u1", "10.8.0.2")
	t.Setenv("time_unix", "5000")
	t.Setenv("bytes_received", "999")
	t.Setenv("bytes_sent", "0")
	if code := Disconnect(tr.config(), ""); code != 0 {
		t.Fatalf("Disconnect = %d, want 0", code)
	}
	if got := tr.usageTotal(t, "u1"); got != 0 {
		t.Fatalf("same-second replacement banked %d bytes under the new session, want 0", got)
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("same-second replacement deleted the new marker: %v", err)
	}
}

// TestDisconnectLegacyOneSecondSkew: a pre-upgrade marker stores hook-run
// time as connection_started, which may differ from time_unix by a second;
// its final banking must not be falsely rejected.
func TestDisconnectLegacyOneSecondSkew(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=0\n")
	markerPath := filepath.Join(tr.sessions, "u1.10.8.0.2")
	if err := store.WriteMarker(markerPath, store.Marker{
		CommonName: "u1", PoolIP: "10.8.0.2", TrustedIP: "9.9.9.9", TrustedPort: "5001",
		Created: 5000, SessionID: "legacy-session", ConnectedAt: 5000,
	}); err != nil {
		t.Fatal(err)
	}
	setClientEnv(t, "u1", "10.8.0.2")
	t.Setenv("time_unix", "5001") // actual start, one second after hook-run time
	t.Setenv("bytes_received", "25")
	t.Setenv("bytes_sent", "15")
	if code := Disconnect(tr.config(), ""); code != 0 {
		t.Fatalf("Disconnect = %d, want 0", code)
	}
	if got := tr.usageTotal(t, "u1"); got != 40 {
		t.Fatalf("legacy skewed disconnect lost final bytes: total=%d, want 40", got)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatal("legacy disconnect left the marker behind")
	}
}

// TestUnlimitedPoolReuseBanksDisplaced: a limit-0 connect banks the
// displaced old generation's unpolled bytes before replacing its marker;
// already-polled bytes stay counted exactly once.
func TestUnlimitedPoolReuseBanksDisplaced(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=0\ndisabled=0\n")
	setClientEnv(t, "u1", "10.8.0.3")
	t.Setenv("time_unix", "6000")
	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("first Connect = %d, want 0", code)
	}
	markerPath := filepath.Join(tr.sessions, "u1.10.8.0.3")
	if _, ok := store.ReadMarker(markerPath); !ok {
		t.Fatal("gen1 marker missing")
	}
	// Status shows gen1 with 30 bytes that no poll has banked yet;
	// gen2 reuses the pool.
	status := "CLIENT_LIST\tu1\t9.9.9.9:5001\t10.8.0.3\t\t30\t0\tfixture\t6000\tUNDEF\t1\n"
	if err := os.WriteFile(tr.status, []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	setClientEnv(t, "u1", "10.8.0.3")
	t.Setenv("time_unix", "7000")
	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("second Connect = %d, want 0", code)
	}
	if got := tr.usageTotal(t, "u1"); got != 30 {
		t.Fatalf("displaced banking total=%d, want 30 (unpolled bytes banked on reuse)", got)
	}
	// Delayed gen1 disconnect must be ignored against the gen2 marker.
	setClientEnv(t, "u1", "10.8.0.3")
	t.Setenv("time_unix", "6000")
	t.Setenv("bytes_received", "50")
	t.Setenv("bytes_sent", "0")
	if code := Disconnect(tr.config(), ""); code != 0 {
		t.Fatalf("delayed Disconnect = %d, want 0", code)
	}
	if got := tr.usageTotal(t, "u1"); got != 30 {
		t.Fatalf("delayed disconnect changed total to %d, want 30", got)
	}
	// Gen2 disconnect banks normally.
	t.Setenv("time_unix", "7000")
	t.Setenv("bytes_received", "4")
	t.Setenv("bytes_sent", "6")
	if code := Disconnect(tr.config(), ""); code != 0 {
		t.Fatalf("gen2 Disconnect = %d, want 0", code)
	}
	if got := tr.usageTotal(t, "u1"); got != 40 {
		t.Fatalf("total=%d, want 40", got)
	}
}

// TestUnlimitedPoolReuseDedupesPolledBytes: when the displaced
// generation's bytes were already observed by a poll, banking them at
// replacement time must not count them twice.
func TestUnlimitedPoolReuseDedupesPolledBytes(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=0\ndisabled=0\n")
	setClientEnv(t, "u1", "10.8.0.4")
	t.Setenv("time_unix", "8000")
	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("first Connect = %d, want 0", code)
	}
	gen1, ok := store.ReadMarker(filepath.Join(tr.sessions, "u1.10.8.0.4"))
	if !ok {
		t.Fatal("gen1 marker missing")
	}
	if _, err := store.RecordSessionUsage(tr.usage, "u1", gen1.SessionID, 25, false); err != nil {
		t.Fatal(err)
	}
	status := "CLIENT_LIST\tu1\t9.9.9.9:5001\t10.8.0.4\t\t25\t0\tfixture\t8000\tUNDEF\t1\n"
	if err := os.WriteFile(tr.status, []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	setClientEnv(t, "u1", "10.8.0.4")
	t.Setenv("time_unix", "9000")
	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("second Connect = %d, want 0", code)
	}
	if got := tr.usageTotal(t, "u1"); got != 25 {
		t.Fatalf("total=%d, want 25 (polled bytes counted exactly once)", got)
	}
}

// TestDisconnectRetainsReceiptUntilMarkerCleanup: after a completed counter
// write, a retried disconnect (marker still present) must not add bytes
// again, and clears the marker once cleanup succeeds.
func TestDisconnectRetainsReceiptUntilMarkerCleanup(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=0\n")
	setClientEnv(t, "u1", "10.8.0.9")
	t.Setenv("time_unix", "4000")
	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect = %d, want 0", code)
	}
	markerPath := filepath.Join(tr.sessions, "u1.10.8.0.9")
	m, ok := store.ReadMarker(markerPath)
	if !ok {
		t.Fatal("marker missing")
	}
	// Simulate: final bytes already committed, marker removal failed.
	if _, err := store.RecordSessionUsage(tr.usage, "u1", m.SessionID, 40, true); err != nil {
		t.Fatal(err)
	}
	// Retried disconnect with the same counters.
	t.Setenv("bytes_received", "25")
	t.Setenv("bytes_sent", "15")
	if code := Disconnect(tr.config(), ""); code != 0 {
		t.Fatalf("retry Disconnect = %d, want 0", code)
	}
	if got := tr.usageTotal(t, "u1"); got != 40 {
		t.Fatalf("retry double-counted: total=%d, want 40", got)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatal("retry did not clear the completed marker")
	}
}
