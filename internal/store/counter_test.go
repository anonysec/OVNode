// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestSessionUsageCountsOnlyIncrements pins the v2 counter regression:
// repeated polls, a closed replay, and a new session.
func TestSessionUsageCountsOnlyIncrements(t *testing.T) {
	dir := t.TempDir()
	steps := []struct {
		id     string
		bytes  uint64
		closed bool
		total  uint64
	}{
		{"A", 100, false, 100},
		{"A", 100, false, 100},
		{"A", 150, true, 150},
		{"A", 150, true, 150},
		{"B", 20, false, 170},
	}
	for _, step := range steps {
		state, err := RecordSessionUsage(dir, "alice", step.id, step.bytes, step.closed)
		if err != nil {
			t.Fatal(err)
		}
		if state.Total != step.total {
			t.Fatalf("session %s total=%d, want %d", step.id, state.Total, step.total)
		}
	}
}

// TestCounterResetPreservesLiveOffsets: a live 100-byte offset survives
// reset; the next 120-byte observation contributes 20, and the epoch moves.
func TestCounterResetPreservesLiveOffsets(t *testing.T) {
	dir := t.TempDir()
	before, err := RecordSessionUsage(dir, "alice", "A", 100, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := ResetUsage(dir, "alice"); err != nil {
		t.Fatal(err)
	}
	after, err := RecordSessionUsage(dir, "alice", "A", 120, false)
	if err != nil {
		t.Fatal(err)
	}
	if after.Total != 20 {
		t.Fatalf("total=%d, want 20", after.Total)
	}
	if after.Epoch == before.Epoch {
		t.Fatal("epoch did not rotate on reset")
	}
	// Closed receipts are dropped by reset.
	closed, err := RecordSessionUsage(dir, "alice", "C", 500, true)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Total != 520 {
		t.Fatalf("total=%d, want 520", closed.Total)
	}
	if err := ResetUsage(dir, "alice"); err != nil {
		t.Fatal(err)
	}
	st, err := ReadUsageState(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Sessions["C"]; ok {
		t.Fatal("closed receipt survived reset")
	}
}

// TestCounterMalformedIsUnavailable: corrupt, empty, unknown-version and
// incomplete v2 files are errors, never a zero total.
func TestCounterMalformedIsUnavailable(t *testing.T) {
	cases := map[string]string{
		"corrupt":          "not a counter",
		"empty":            "",
		"whitespace":       "  \n",
		"trailing":         `{"version":2,"epoch":"e1","total":5,"sessions":{}} garbage`,
		"unknown version":  `{"version":3,"epoch":"e1","total":5,"sessions":{}}`,
		"missing epoch":    `{"version":2,"total":5,"sessions":{}}`,
		"empty epoch":      `{"version":2,"epoch":"","total":5,"sessions":{}}`,
		"missing total":    `{"version":2,"epoch":"e1","sessions":{}}`,
		"missing sessions": `{"version":2,"epoch":"e1","total":5}`,
		"unknown field":    `{"version":2,"epoch":"e1","total":5,"sessions":{},"future":1}`,
		"negative total":   `{"version":2,"epoch":"e1","total":-5,"sessions":{}}`,
		"fractional":       `{"version":2,"epoch":"e1","total":1.5,"sessions":{}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "alice"), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadUsageState(dir, "alice"); err == nil {
				t.Fatalf("malformed counter %q returned no error", body)
			}
			if _, err := RecordSessionUsage(dir, "alice", "S1", 10, false); err == nil {
				t.Fatal("record over malformed counter returned no error")
			}
		})
	}
}

// TestCounterMarkerKeyIsFilename: the stored marker_key is the marker file
// name, not the generation-suffixed accounting ID.
func TestCounterMarkerKeyIsFilename(t *testing.T) {
	dir := t.TempDir()
	id := "alice.10.66.0.2.0123456789abcdef"
	st, err := RecordSessionUsage(dir, "alice", id, 10, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Sessions[id].MarkerKey; got != "alice.10.66.0.2" {
		t.Fatalf("marker_key=%q, want alice.10.66.0.2", got)
	}
}

// TestCounterReceiptRetentionAndPrune: a closed receipt survives while its
// marker is present and is retired once the marker is confirmed gone.
func TestCounterReceiptRetentionAndPrune(t *testing.T) {
	dir := t.TempDir()
	if _, err := RecordSessionUsage(dir, "alice", "done", 50, true); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordSessionUsage(dir, "alice", "live", 10, false); err != nil {
		t.Fatal(err)
	}
	// Marker still present (cleanup failed): receipt retained.
	if err := PruneReceipts(dir, "alice", map[string]bool{"done": true}); err != nil {
		t.Fatal(err)
	}
	st, err := ReadUsageState(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Sessions["done"]; !ok {
		t.Fatal("closed receipt pruned while its generation could still replay")
	}
	// Marker confirmed absent: receipt retired, live offset kept.
	if err := PruneReceipts(dir, "alice", map[string]bool{"live": true}); err != nil {
		t.Fatal(err)
	}
	st, err = ReadUsageState(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Sessions["done"]; ok {
		t.Fatal("closed receipt retained after confirmed marker absence")
	}
	if st.Total != 60 {
		t.Fatalf("total=%d, want 60 (pruning must not change totals)", st.Total)
	}
}

// TestCounterReceiptGrowthIsBounded: many completed sessions do not grow
// the persisted file once their markers are gone.
func TestCounterReceiptGrowthIsBounded(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 50; i++ {
		if _, err := RecordSessionUsage(dir, "alice", "s"+string(rune('a'+i%26))+string(rune('0'+i/26)), uint64(i+1), true); err != nil {
			t.Fatal(err)
		}
	}
	if err := PruneReceipts(dir, "alice", map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	st, err := ReadUsageState(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Sessions) != 0 {
		t.Fatalf("retained %d closed receipts, want 0", len(st.Sessions))
	}
	data, err := os.ReadFile(filepath.Join(dir, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 200 {
		t.Fatalf("persisted counter is %d bytes after pruning, want bounded", len(data))
	}
}

// TestCounterFailedWritePropagates: an unwritable counter surfaces an
// error instead of reporting success.
func TestCounterFailedWritePropagates(t *testing.T) {
	dir := t.TempDir()
	// A directory where the counter file should be makes reads fail.
	if err := os.Mkdir(filepath.Join(dir, "alice"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordSessionUsage(dir, "alice", "S1", 10, false); err == nil {
		t.Fatal("record over unreadable counter returned no error")
	}
	if _, err := ReadUsageState(dir, "alice"); err == nil {
		t.Fatal("read of directory counter returned no error")
	}
	// An empty session ID is rejected, not stored.
	if _, err := RecordSessionUsage(dir, "bob", "", 10, false); err == nil {
		t.Fatal("empty session id returned no error")
	}
}

// TestCounterConcurrentFinalUpdates: simultaneous final updates for
// different sessions of one CN all land exactly once.
func TestCounterConcurrentFinalUpdates(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "s" + string(rune('a'+i))
			if _, err := RecordSessionUsage(dir, "alice", id, 100, true); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	st, err := ReadUsageState(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 2000 {
		t.Fatalf("total=%d, want 2000", st.Total)
	}
	if len(st.Sessions) != 20 {
		t.Fatalf("sessions=%d, want 20", len(st.Sessions))
	}
}
