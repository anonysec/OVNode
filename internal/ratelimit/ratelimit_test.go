// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ratelimit

import (
	"strconv"
	"testing"
	"time"
)

func TestAllowHeavyAndPruning(t *testing.T) {
	l := New()
	for i := 0; i < heavyMax; i++ {
		ok, _ := l.AllowHeavy("client1")
		if !ok {
			t.Fatalf("call %d should be allowed", i)
		}
	}
	// Exceeded
	ok, retry := l.AllowHeavy("client1")
	if ok {
		t.Fatal("call over heavyMax should be rejected")
	}
	if retry <= 0 {
		t.Fatalf("expected positive retry duration, got %v", retry)
	}

	// Pruning test: populate more than maxBuckets
	now := time.Now()
	for i := 0; i < maxBuckets+20; i++ {
		l.heavy.hits["c"+strconv.Itoa(i)] = timeEntry{ts: []time.Time{now.Add(-2 * span60s)}}
	}
	l.prune(now)
	if len(l.heavy.hits) > maxBuckets {
		t.Fatalf("heavy.hits len = %d, want <= %d", len(l.heavy.hits), maxBuckets)
	}
}
