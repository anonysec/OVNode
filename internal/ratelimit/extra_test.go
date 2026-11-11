package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

func TestAllowGlobalSeparateFromPerIP(t *testing.T) {
	l := New()
	// per-IP bucket full should not imply global full
	for i := 0; i < maxRequests; i++ {
		if ok, _ := l.Allow("ip1"); !ok {
			t.Fatalf("per-ip call %d rejected", i)
		}
	}
	// global still has capacity
	ok, _ := l.AllowGlobal()
	if !ok {
		t.Fatal("global should still allow after per-ip exhaustion")
	}
}

func TestFailedAuthBackoff(t *testing.T) {
	l := New()
	for i := 0; i < failedMax; i++ {
		l.RecordFailedAuth("ip2")
	}
	blocked, retry := l.FailedBlocked("ip2")
	if !blocked {
		t.Fatal("expected blocked after failedMax")
	}
	if retry <= 0 {
		t.Fatalf("expected positive retry, got %v", retry)
	}
	if blocked, _ := l.FailedBlocked("other"); blocked {
		t.Fatal("other IP should not be blocked")
	}
}

func TestPruneEvictsTenPercentAtOnce(t *testing.T) {
	l := New()
	for i := 0; i < 12000; i++ {
		l.Allow(fmt.Sprintf("c%d", i))
	}
	if len(l.t.hits) > maxBuckets {
		t.Fatalf("t.hits len = %d, want <= %d (cap with 10%% eviction)", len(l.t.hits), maxBuckets)
	}
}

// The expiry sweep is time-gated, not per-request. Force it and check the
// stale bucket is gone without another 12,000 calls.
func TestTrimDropsExpiredBuckets(t *testing.T) {
	w := &window{max: 1, span: 5 * time.Millisecond, hits: map[string]timeEntry{}}
	w.allow("old")
	time.Sleep(10 * time.Millisecond)
	w.lastTrim = time.Time{}
	w.allow("new")
	if _, ok := w.hits["old"]; ok {
		t.Fatal("expired bucket survived the sweep")
	}
	if _, ok := w.hits["new"]; !ok {
		t.Fatal("fresh bucket was dropped")
	}
}

// A second request inside the gate must not sweep the map again.
func TestTrimIsTimeGated(t *testing.T) {
	w := &window{max: 1, span: time.Hour, hits: map[string]timeEntry{}}
	w.allow("a")
	gated := w.lastTrim
	w.allow("b")
	if !w.lastTrim.Equal(gated) {
		t.Fatal("the sweep ran again inside the interval")
	}
}
