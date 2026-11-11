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
	start := time.Now()
	for i := 0; i < 12000; i++ {
		l.Allow(fmt.Sprintf("c%d", i))
	}
	if elapsed := time.Since(start); elapsed >= 30*time.Second {
		t.Fatalf("loop took %v, want under 30s", elapsed)
	}
	if len(l.t.hits) > maxBuckets {
		t.Fatalf("t.hits len = %d, want <= %d (cap with 10%% eviction)", len(l.t.hits), maxBuckets)
	}
}
