// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package events

import (
	"encoding/json"
	"testing"
	"time"
)

func collect(ch <-chan Payload, n int, wait time.Duration) []Payload {
	var out []Payload
	deadline := time.After(wait)
	for len(out) < n {
		select {
		case p := <-ch:
			out = append(out, p)
		case <-deadline:
			return out
		}
	}
	return out
}

func TestPublishBumpsRevision(t *testing.T) {
	h := NewHub()
	sub := h.Subscribe()
	h.Publish("sessions", map[string]string{"a": "1"})
	h.Publish("usage", map[string]string{"b": "2"})
	got := collect(sub.C(), 2, time.Second)
	if len(got) != 2 {
		t.Fatalf("delivered %d payloads, want 2", len(got))
	}
	if got[0].Revision != 1 || got[1].Revision != 2 {
		t.Fatalf("revisions %d then %d, want 1 then 2", got[0].Revision, got[1].Revision)
	}
	if got[0].Kind != "sessions" || got[1].Kind != "usage" {
		t.Fatalf("kinds %q %q, want sessions usage", got[0].Kind, got[1].Kind)
	}
	var body map[string]string
	if err := json.Unmarshal(got[0].Data, &body); err != nil {
		t.Fatalf("data not marshaled: %v", err)
	}
	if body["a"] != "1" {
		t.Fatalf("data %s, want {a:1}", got[0].Data)
	}
}

func TestPublishDropsOldestWhenFull(t *testing.T) {
	h := NewHub()
	sub := h.Subscribe()
	for i := 0; i < queueDepth*2; i++ {
		h.Publish("sessions", i)
	}
	got := collect(sub.C(), 1, time.Second)
	if len(got) != 1 {
		t.Fatalf("delivered %d, want exactly one retained frame", len(got))
	}
	var n int
	if err := json.Unmarshal(got[0].Data, &n); err != nil {
		t.Fatal(err)
	}
	if n != queueDepth {
		t.Fatalf("queue front %d, want %d (oldest dropped, newest window retained)", n, queueDepth)
	}
	if got[0].Revision != int64(queueDepth+1) {
		t.Fatalf("revision %d, want %d (dropped frames still count)", got[0].Revision, queueDepth+1)
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	h := NewHub()
	sub := h.Subscribe()
	h.Unsubscribe(sub)
	h.Publish("sessions", 1)
	got := collect(sub.C(), 1, 50*time.Millisecond)
	if len(got) != 0 {
		t.Fatal("payload delivered after Unsubscribe")
	}
}

func TestCount(t *testing.T) {
	h := NewHub()
	if h.Count() != 0 {
		t.Fatal("new hub is not empty")
	}
	sub := h.Subscribe()
	if h.Count() != 1 {
		t.Fatal("Count missed one subscriber")
	}
	h.Unsubscribe(sub)
	if h.Count() != 0 {
		t.Fatal("Unsubscribe did not release the slot")
	}
}

func TestPublishMarshalFailureSkipsRevision(t *testing.T) {
	h := NewHub()
	sub := h.Subscribe()
	h.Publish("sessions", func() {}) // unmarshalable
	h.Publish("sessions", 7)
	got := collect(sub.C(), 1, time.Second)
	if len(got) != 1 || got[0].Revision != 1 {
		t.Fatalf("unmarshalable payload spent a revision: %+v", got)
	}
}
