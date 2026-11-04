// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

const (
	window       = 60 * time.Second
	failedWindow = 5 * time.Minute
	maxRequests  = 120
	globalMax    = 600
	heavyMax     = 60
	failedMax    = 10
	maxBuckets   = 10000
)

type bucket struct {
	ts   []time.Time
	last time.Time
}

type Limiter struct {
	mu        sync.Mutex
	lastPrune time.Time
	buckets   map[string]*bucket
	global    *bucket
	heavy     map[string]*bucket
	failed    map[string]*bucket
}

func New() *Limiter {
	return &Limiter{
		buckets: map[string]*bucket{},
		global:  &bucket{},
		heavy:   map[string]*bucket{},
		failed:  map[string]*bucket{},
	}
}

func keyFor(client string) string {
	h := sha256.Sum256([]byte(client))
	return hex.EncodeToString(h[:])[:32]
}

// trimExpired drops timestamps older than the window in place.
func trimExpired(b *bucket, now time.Time, w time.Duration) {
	i := 0
	for i < len(b.ts) && now.Sub(b.ts[i]) >= w {
		i++
	}
	if i > 0 {
		b.ts = b.ts[i:]
	}
}

func (l *Limiter) prune(now time.Time) {
	if !l.lastPrune.IsZero() && now.Sub(l.lastPrune) < 10*time.Second &&
		len(l.buckets) < maxBuckets && len(l.heavy) < maxBuckets &&
		len(l.failed) < maxBuckets {
		return
	}
	l.lastPrune = now

	pruneMap := func(m map[string]*bucket, w time.Duration) {
		for k, b := range m {
			trimExpired(b, now, w)
			if len(b.ts) == 0 {
				delete(m, k)
			}
		}
		if len(m) >= maxBuckets {
			// LRU eviction: sort by last use, drop oldest.
			type kv struct {
				k    string
				last time.Time
			}
			keys := make([]kv, 0, len(m))
			for k, b := range m {
				keys = append(keys, kv{k, b.last})
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i].last.Before(keys[j].last) })
			excess := len(m) - maxBuckets + 1
			for i := 0; i < excess && i < len(keys); i++ {
				delete(m, keys[i].k)
			}
		}
	}

	pruneMap(l.buckets, window)
	pruneMap(l.heavy, window)
	pruneMap(l.failed, failedWindow)

	// global single bucket
	trimExpired(l.global, now, window)
}

func (l *Limiter) Allow(client string) (bool, time.Duration) {
	now := time.Now()
	key := keyFor(client)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{}
		l.buckets[key] = b
	}
	trimExpired(b, now, window)
	if len(b.ts) >= maxRequests {
		b.last = now
		retry := window - now.Sub(b.ts[0])
		if retry < time.Second {
			retry = time.Second
		}
		return false, retry
	}
	b.ts = append(b.ts, now)
	b.last = now
	return true, 0
}

func (l *Limiter) AllowHeavy(client string) (bool, time.Duration) {
	now := time.Now()
	key := keyFor(client)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(now)

	b, ok := l.heavy[key]
	if !ok {
		b = &bucket{}
		l.heavy[key] = b
	}
	trimExpired(b, now, window)
	if len(b.ts) >= heavyMax {
		b.last = now
		retry := window - now.Sub(b.ts[0])
		if retry < time.Second {
			retry = time.Second
		}
		return false, retry
	}
	b.ts = append(b.ts, now)
	b.last = now
	return true, 0
}

func (l *Limiter) AllowGlobal() (bool, time.Duration) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(now)

	b := l.global
	trimExpired(b, now, window)
	if len(b.ts) >= globalMax {
		retry := window - now.Sub(b.ts[0])
		if retry < time.Second {
			retry = time.Second
		}
		return false, retry
	}
	b.ts = append(b.ts, now)
	return true, 0
}

// FailedBlocked reports whether client is currently locked out for repeated
// failed authentication, without recording a new failure.
func (l *Limiter) FailedBlocked(client string) (bool, time.Duration) {
	now := time.Now()
	key := keyFor(client)
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.failed[key]
	if b == nil {
		return false, 0
	}
	trimExpired(b, now, failedWindow)
	if len(b.ts) >= failedMax {
		retry := failedWindow - now.Sub(b.ts[0])
		if retry < time.Second {
			retry = time.Second
		}
		return true, retry
	}
	return false, 0
}

// RecordFailedAuth records one failed authentication attempt for client.
func (l *Limiter) RecordFailedAuth(client string) {
	now := time.Now()
	key := keyFor(client)
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.failed[key]
	if !ok {
		b = &bucket{}
		l.failed[key] = b
	}
	trimExpired(b, now, failedWindow)
	b.ts = append(b.ts, now)
	b.last = now
}

func (l *Limiter) AllowFailedAuth(client string) (bool, time.Duration) {
	now := time.Now()
	key := keyFor(client)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(now)

	b, ok := l.failed[key]
	if !ok {
		b = &bucket{}
		l.failed[key] = b
	}
	trimExpired(b, now, failedWindow)
	if len(b.ts) >= failedMax {
		retry := failedWindow - now.Sub(b.ts[0])
		if retry < time.Second {
			retry = time.Second
		}
		b.last = now
		return false, retry
	}
	b.ts = append(b.ts, now)
	b.last = now
	return true, 0
}
