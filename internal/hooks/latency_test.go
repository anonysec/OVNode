// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"sort"
	"testing"
	"time"
)

// TestAllowPathLatencyBudget pins the reconnect-storm budget.
//
// The allow path is the hot one: a hundred phones rejoining at once must
// not make the node slow. The bash hook paid a fork per connect (awk, then
// python for the take-over); the Go hook reads the status file in process
// and takes a lock, so the whole decision stays in the low milliseconds.
func TestAllowPathLatencyBudget(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=0\n")
	setClientEnv(t, "u1", "10.8.0.2")
	cfg := tr.config()

	// Warm-up run: the first connect pays for the cold page cache.
	if code := Connect(cfg, ""); code != 0 {
		t.Fatalf("Connect exit code = %d, want 0", code)
	}

	const runs = 50
	durations := make([]time.Duration, 0, runs)
	for i := 0; i < runs; i++ {
		start := time.Now()
		if code := Connect(cfg, ""); code != 0 {
			t.Fatalf("Connect exit code = %d, want 0", code)
		}
		durations = append(durations, time.Since(start))
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p50 := durations[len(durations)/2]
	p99 := durations[len(durations)*99/100]
	t.Logf("allow path: p50=%s p99=%s", p50, p99)
	if p99 > 25*time.Millisecond {
		t.Fatalf("allow path p99 = %s, want under 25ms", p99)
	}
}
