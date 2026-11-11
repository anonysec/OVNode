// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ratelimit

import (
	"slices"
	"sync"
	"time"
)

const (
	span60s      = 60 * time.Second
	failedWindow = 5 * time.Minute
	maxRequests  = 120
	globalMax    = 600
	heavyMax     = 60
	failedMax    = 10
	maxBuckets   = 10000
)

type timeEntry struct {
	ts   []time.Time
	last time.Time
}

type window struct {
	max  int
	span time.Duration
	hits map[string]timeEntry
}

type Limiter struct {
	mu     sync.Mutex
	t      *window
	global *window
	heavy  *window
	failed *window
}

func New() *Limiter {
	return &Limiter{
		t:      &window{max: maxRequests, span: span60s, hits: map[string]timeEntry{}},
		global: &window{max: globalMax, span: span60s, hits: map[string]timeEntry{}},
		heavy:  &window{max: heavyMax, span: span60s, hits: map[string]timeEntry{}},
		failed: &window{max: failedMax, span: failedWindow, hits: map[string]timeEntry{}},
	}
}

func (w *window) trim(now time.Time) {
	for k, e := range w.hits {
		i := 0
		for i < len(e.ts) && now.Sub(e.ts[i]) >= w.span {
			i++
		}
		if i > 0 {
			e.ts = e.ts[i:]
		}
		if len(e.ts) == 0 {
			delete(w.hits, k)
			continue
		}
		if i > 0 {
			w.hits[k] = e
		}
	}
}

func (w *window) cap(now time.Time) {
	if len(w.hits) < maxBuckets {
		return
	}
	keys := make([]string, 0, len(w.hits))
	for k := range w.hits {
		keys = append(keys, k)
	}
	target := maxBuckets - maxBuckets/10
	slices.SortFunc(keys, func(a, b string) int { return w.hits[a].last.Compare(w.hits[b].last) })
	for i := 0; i < len(keys)-target; i++ {
		delete(w.hits, keys[i])
	}
}

func (w *window) allow(key string) (bool, time.Duration) {
	now := time.Now()
	w.trim(now)
	w.cap(now)
	e := w.hits[key]
	if len(e.ts) >= w.max {
		retry := w.span - now.Sub(e.ts[0])
		if retry < time.Second {
			retry = time.Second
		}
		return false, retry
	}
	e.ts = append(e.ts, now)
	e.last = now
	w.hits[key] = e
	return true, 0
}

func (w *window) blocked(key string) (bool, time.Duration) {
	now := time.Now()
	w.trim(now)
	e := w.hits[key]
	if len(e.ts) >= w.max {
		retry := w.span - now.Sub(e.ts[0])
		if retry < time.Second {
			retry = time.Second
		}
		return true, retry
	}
	return false, 0
}

func (w *window) record(key string) {
	now := time.Now()
	w.trim(now)
	e := w.hits[key]
	e.ts = append(e.ts, now)
	e.last = now
	w.hits[key] = e
}

func (l *Limiter) Allow(client string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.t.allow(client)
}
func (l *Limiter) AllowHeavy(client string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.heavy.allow(client)
}
func (l *Limiter) AllowGlobal() (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.global.allow("")
}
func (l *Limiter) FailedBlocked(client string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failed.blocked(client)
}
func (l *Limiter) RecordFailedAuth(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failed.record(client)
}
