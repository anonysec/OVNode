// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"sync"
	"time"
)

// cache is a TTL cache for a map value.
//
// The panel pushes a name or a usage total once and then only polls, so
// rebuilding either map on every request would stat the whole tree per poll.
//
// The cache is scoped to the directory it describes: a node can be pointed
// at another tree at runtime, and one tree's names must never be served for
// another.
type cache[T any] struct {
	mu   sync.Mutex
	at   time.Time
	dir  string
	data map[string]T
	ttl  time.Duration
}

func newCache[T any](ttl time.Duration) *cache[T] {
	return &cache[T]{ttl: ttl}
}

func (c *cache[T]) get(dir string) (map[string]T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data == nil || c.dir != dir || time.Since(c.at) > c.ttl {
		return nil, false
	}
	out := make(map[string]T, len(c.data))
	for k, v := range c.data {
		out[k] = v
	}
	return out, true
}

func (c *cache[T]) set(dir string, data map[string]T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = data
	c.dir = dir
	c.at = time.Now()
}

func (c *cache[T]) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = nil
}

var (
	nameCacheInst  = newCache[string](30 * time.Second)
	usageCacheInst = newCache[uint64](8 * time.Second)
)

// InvalidateNameCache clears the name cache.
func InvalidateNameCache() { nameCacheInst.invalidate() }

// NameCacheGet returns cached name map if fresh.
func NameCacheGet(dir string) (map[string]string, bool) { return nameCacheInst.get(dir) }

// NameCacheSet stores name map.
func NameCacheSet(dir string, data map[string]string) { nameCacheInst.set(dir, data) }

// UsageCacheGet/Set/Invalidate
func UsageCacheGet(dir string) (map[string]uint64, bool) { return usageCacheInst.get(dir) }
func UsageCacheSet(dir string, data map[string]uint64)   { usageCacheInst.set(dir, data) }
func InvalidateUsageCache()                              { usageCacheInst.invalidate() }
