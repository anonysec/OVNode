// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package events

import (
	"encoding/json"
	"sync"
)

// queueDepth bounds one subscriber's pending payloads. A slow SSE client drops
// its oldest event rather than stalling the publisher.
const queueDepth = 100

// Payload is one event on the hub. Revision is monotonic within a hub
// lifetime; a stream consumer trusts the snapshot on (re)connect and uses the
// revision only to drop out-of-order frames on the same connection.
type Payload struct {
	Kind     string          `json:"kind"`
	Revision int64           `json:"revision"`
	Data     json.RawMessage `json:"data"`
}

// Hub fans agent-side events out to every open /sync/events stream.
type Hub struct {
	mu       sync.Mutex
	subs     map[*Sub]struct{}
	revision int64
}

// Sub is one subscriber handle; the SSE handler keeps it to unsubscribe.
type Sub struct {
	ch chan Payload
}

// C exposes the receive side.
func (s *Sub) C() <-chan Payload { return s.ch }

// NewHub builds an empty hub.
func NewHub() *Hub {
	return &Hub{subs: map[*Sub]struct{}{}}
}

// Subscribe registers a subscriber.
func (h *Hub) Subscribe() *Sub {
	s := &Sub{ch: make(chan Payload, queueDepth)}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

// Unsubscribe drops a subscriber.
func (h *Hub) Unsubscribe(s *Sub) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
}

// Count reports how many streams are attached; the watcher and tickers idle
// entirely while it is zero.
func (h *Hub) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// Publish delivers one event to every subscriber. Never blocks: a full
// subscriber queue loses its oldest entry. A payload that fails to marshal is
// skipped without spending a revision.
func (h *Hub) Publish(kind string, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.revision++
	p := Payload{Kind: kind, Revision: h.revision, Data: raw}
	for s := range h.subs {
		select {
		case s.ch <- p:
		default:
			select {
			case <-s.ch:
			default:
			}
			select {
			case s.ch <- p:
			default:
			}
		}
	}
}
