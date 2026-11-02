// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

const (
	window      = 60 * time.Second
	maxRequests = 120
	globalMax   = 600
	heavyMax    = 60
	maxBuckets  = 10000
)

type bucket struct {
	ts []time.Time
}

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	global  *bucket
	heavy   map[string]*bucket
}

func New() *Limiter {
	return &Limiter{
		buckets: map[string]*bucket{},
		global:  &bucket{},
		heavy:   map[string]*bucket{},
	}
}

func keyFor(client string) string {
	h := sha256.Sum256([]byte(client))
	return hex.EncodeToString(h[:])[:32]
}

func (l *Limiter) prune(now time.Time) {
	for k, b := range l.buckets {
		fresh := make([]time.Time, 0, len(b.ts))
		for _, t := range b.ts {
			if now.Sub(t) < window {
				fresh = append(fresh, t)
			}
		}
		if len(fresh) == 0 {
			delete(l.buckets, k)
		} else {
			b.ts = fresh
		}
	}
	for len(l.buckets) >= maxBuckets {
		// evict oldest bucket
		var oldestKey string
		var oldest time.Time
		first := true
		for k, b := range l.buckets {
			if len(b.ts) == 0 {
				oldestKey = k
				break
			}
			if first || b.ts[0].Before(oldest) {
				oldest = b.ts[0]
				oldestKey = k
				first = false
			}
		}
		delete(l.buckets, oldestKey)
	}
	for k, b := range l.heavy {
		fresh := make([]time.Time, 0, len(b.ts))
		for _, t := range b.ts {
			if now.Sub(t) < window {
				fresh = append(fresh, t)
			}
		}
		if len(fresh) == 0 {
			delete(l.heavy, k)
		} else {
			b.ts = fresh
		}
	}
	for len(l.heavy) >= maxBuckets {
		var oldestKey string
		var oldest time.Time
		first := true
		for k, b := range l.heavy {
			if len(b.ts) == 0 {
				oldestKey = k
				break
			}
			if first || b.ts[0].Before(oldest) {
				oldest = b.ts[0]
				oldestKey = k
				first = false
			}
		}
		delete(l.heavy, oldestKey)
	}
}

func (l *Limiter) Allow(client string) (bool, time.Duration) {
	now := time.Now()
	key := keyFor(client)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(now)

	// global
	gHits := []time.Time{}
	for _, t := range l.global.ts {
		if now.Sub(t) < window {
			gHits = append(gHits, t)
		}
	}
	l.global.ts = gHits
	if len(gHits) >= globalMax {
		retry := window - now.Sub(gHits[0])
		if retry < time.Second {
			retry = time.Second
		}
		return false, retry
	}
	gHits = append(gHits, now)
	l.global.ts = gHits

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{}
		l.buckets[key] = b
	}
	hits := []time.Time{}
	for _, t := range b.ts {
		if now.Sub(t) < window {
			hits = append(hits, t)
		}
	}
	if len(hits) >= maxRequests {
		b.ts = hits
		retry := window - now.Sub(hits[0])
		if retry < time.Second {
			retry = time.Second
		}
		return false, retry
	}
	hits = append(hits, now)
	b.ts = hits
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
	hits := []time.Time{}
	for _, t := range b.ts {
		if now.Sub(t) < window {
			hits = append(hits, t)
		}
	}
	if len(hits) >= heavyMax {
		b.ts = hits
		retry := window - now.Sub(hits[0])
		if retry < time.Second {
			retry = time.Second
		}
		return false, retry
	}
	hits = append(hits, now)
	b.ts = hits
	return true, 0
}
