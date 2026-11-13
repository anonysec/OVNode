// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"ovnode/internal/events"
)

// eventsServer builds a real HTTP server around the route table with a live
// hub, like Run does, plus a client that authenticates the way the panel does.
func eventsServer(t *testing.T) (*events.Hub, *http.Client, string) {
	t.Helper()
	hub := events.NewHub()
	s := testServer(t)
	s.hub = hub
	s.streamSlots = make(chan struct{}, maxEventStreams)
	raw := httptestListener(t)
	srv := &http.Server{Handler: s.routes()}
	go srv.Serve(raw)
	t.Cleanup(func() { srv.Close() })
	base := "http://" + raw.Addr().String()
	client := &http.Client{Transport: &http.Transport{}}
	return hub, client, base
}

// httptestListener grabs a free local port without wrapping TLS.
func httptestListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func openStream(t *testing.T, client *http.Client, base string) (*bufio.Reader, func()) {
	t.Helper()
	// A stalled stream must fail the test instead of blocking the whole
	// package until the 10-minute go-test timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/sync/events", nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	req.Header.Set("key", testKey)
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		t.Fatalf("stream status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		resp.Body.Close()
		cancel()
		t.Fatalf("content type %q", ct)
	}
	return bufio.NewReader(resp.Body), func() {
		resp.Body.Close()
		cancel()
	}
}

func readEvent(t *testing.T, r *bufio.Reader) (string, map[string]any) {
	t.Helper()
	var kind string
	data := map[string]any{}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("stream read: %v", err)
		}
		line = strings.TrimRight(line, "\n")
		switch {
		case line == "":
			return kind, data
		case strings.HasPrefix(line, ":"):
			return "comment", data
		case strings.HasPrefix(line, "event:"):
			kind = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			raw := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if err := json.Unmarshal([]byte(raw), &data); err != nil {
				t.Fatalf("event data not JSON: %v (%s)", err, raw)
			}
		}
	}
}

func TestEventsSnapshotOnConnect(t *testing.T) {
	hub, client, base := eventsServer(t)
	body, close_ := openStream(t, client, base)
	defer close_()
	kind, frame := readEvent(t, body)
	if kind != "snapshot" {
		t.Fatalf("first event %q, want snapshot", kind)
	}
	if rev, ok := frame["revision"].(float64); !ok || rev != 0 {
		t.Fatalf("snapshot revision %v, want 0", frame["revision"])
	}
	data, _ := frame["data"].(map[string]any)
	if _, ok := data["live_sessions"]; !ok {
		t.Fatalf("snapshot body lacks live_sessions: %v", data)
	}
	hub.Publish("sessions", map[string]any{"live_sessions": []any{}})
	kind, _ = readEvent(t, body)
	if kind != "sessions" {
		t.Fatalf("second event %q, want sessions", kind)
	}
}

func TestEventsHeartbeatIsComment(t *testing.T) {
	hub, client, base := eventsServer(t)
	body, close_ := openStream(t, client, base)
	defer close_()
	kind, _ := readEvent(t, body)
	if kind != "snapshot" {
		t.Fatalf("first event %q, want snapshot", kind)
	}
	hub.Publish("heartbeat", nil)
	kind, _ = readEvent(t, body)
	if kind != "comment" {
		t.Fatalf("heartbeat came through as %q, want an SSE comment", kind)
	}
}

func TestEventsForwardOrderAndRevision(t *testing.T) {
	hub, client, base := eventsServer(t)
	body, close_ := openStream(t, client, base)
	defer close_()
	_, _ = readEvent(t, body) // snapshot
	hub.Publish("usage", map[string]any{"totals": map[string]uint64{"2": 7}})
	hub.Publish("sessions", map[string]any{"live_sessions": []any{}})
	kind1, frame1 := readEvent(t, body)
	kind2, frame2 := readEvent(t, body)
	if kind1 != "usage" || kind2 != "sessions" {
		t.Fatalf("order %q then %q, want usage then sessions", kind1, kind2)
	}
	if frame1["revision"].(float64) != 1 || frame2["revision"].(float64) != 2 {
		t.Fatalf("revisions %v %v, want 1 2", frame1["revision"], frame2["revision"])
	}
}

// TestEventsSurvivesGlobalWriteTimeout pins the per-write deadline: a server
// configured with WriteTimeout=1s must keep a stream open past it as long as
// events keep flowing.
func TestEventsSurvivesGlobalWriteTimeout(t *testing.T) {
	hub := events.NewHub()
	s := testServer(t)
	s.hub = hub
	s.streamSlots = make(chan struct{}, maxEventStreams)
	l := httptestListener(t)
	srv := &http.Server{Handler: s.routes(), WriteTimeout: time.Second}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	base := "http://" + l.Addr().String()
	client := &http.Client{Transport: &http.Transport{}}
	body, close_ := openStream(t, client, base)
	defer close_()
	_, _ = readEvent(t, body)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 6; i++ {
			select {
			case <-stop:
				return
			case <-time.After(300 * time.Millisecond):
				hub.Publish("sessions", i)
			}
		}
	}()
	defer close(stop)
	for i := 0; i < 4; i++ {
		kind, frame := readEvent(t, body)
		if kind != "sessions" {
			t.Fatalf("event %d kind %q", i, kind)
		}
		if _, ok := frame["revision"].(float64); !ok {
			t.Fatalf("event %d missing revision", i)
		}
	}
	wg.Wait()
}

func TestEventsCapConcurrentStreams(t *testing.T) {
	_, client, base := eventsServer(t)
	var held []*http.Response
	defer func() {
		for _, resp := range held {
			resp.Body.Close()
		}
	}()
	for i := 0; i < maxEventStreams; i++ {
		req, _ := http.NewRequest(http.MethodGet, base+"/sync/events", nil)
		req.Header.Set("key", testKey)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		held = append(held, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("stream %d status %d", i, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, base+"/sync/events", nil)
	req.Header.Set("key", testKey)
	over, err := client.Do(req)
	if err != nil {
		t.Fatalf("over-cap request: %v", err)
	}
	defer over.Body.Close()
	var env map[string]any
	if err := json.NewDecoder(over.Body).Decode(&env); err != nil {
		t.Fatalf("over-cap body: %v", err)
	}
	// A business failure answers inside the envelope with HTTP 200, never a
	// bare error status.
	if env["success"] != false {
		t.Fatalf("over-cap envelope %v", env)
	}
	if msg, _ := env["msg"].(string); !strings.Contains(msg, "limit") {
		t.Fatalf("over-cap msg %q", msg)
	}
}

func TestEventsNilHubSnapshotOnly(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, http.MethodGet, "/sync/events", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "event: snapshot") {
		t.Fatalf("body %q", rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("content type %q", rec.Header().Get("Content-Type"))
	}
}

func TestEventsUnauthorized(t *testing.T) {
	_, client, base := eventsServer(t)
	req, _ := http.NewRequest(http.MethodGet, base+"/sync/events", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated stream status %d, want 401", resp.StatusCode)
	}
}
