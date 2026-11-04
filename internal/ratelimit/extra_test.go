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
		if ok, _ := l.AllowFailedAuth("ip2"); !ok {
			t.Fatalf("failed auth call %d rejected", i)
		}
	}
	ok, retry := l.AllowFailedAuth("ip2")
	if ok {
		t.Fatal("expected rejection after failedMax")
	}
	if retry <= 0 {
		t.Fatalf("expected positive retry, got %v", retry)
	}
}

func TestLRUEviction(t *testing.T) {
	l := New()
	now := time.Now()
	for i := 0; i < maxBuckets+5; i++ {
		l.buckets["c"+itoa(i)] = &bucket{ts: []time.Time{now}, last: now.Add(time.Duration(i) * time.Millisecond)}
	}
	l.prune(now)
	if len(l.buckets) > maxBuckets {
		t.Fatalf("buckets len = %d, want <= %d", len(l.buckets), maxBuckets)
	}
}

func itoa(i int) string {
	// small helper to avoid import
	b := []byte{}
	if i == 0 {
		return "0"
	}
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestPruneEvictsTenPercentAtOnce(t *testing.T) {
	l := New()
	start := time.Now()
	for i := 0; i < 12000; i++ {
		l.Allow(fmt.Sprintf("c%d", i))
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Fatalf("loop took %v, want under 2s", elapsed)
	}
	if len(l.buckets) >= maxBuckets {
		t.Fatalf("buckets len = %d, want < %d", len(l.buckets), maxBuckets)
	}
}
