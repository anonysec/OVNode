// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ovnode/internal/events"
	"ovnode/internal/ovpn"
)

const (
	// maxEventStreams bounds concurrent panel streams; the panel holds one
	// per node, so the cap only trips on misbehaving clients.
	maxEventStreams = 8
	// eventWriteTimeout is extended before every write: the server's global
	// WriteTimeout would otherwise cut the stream at 30 s.
	eventWriteTimeout = 10 * time.Second
)

// eventsSnapshot is the payload provider: exactly the /sync/sessions body,
// so the panel consumer decodes one shape whether it polls or streams.
func eventsSnapshot() (any, error) {
	return ovpn.UserDiagnostics("", 8), nil
}

// sseFrame is one event's data line: revision plus the payload.
type sseFrame struct {
	Revision int64           `json:"revision"`
	Data     json.RawMessage `json:"data"`
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeFail(w, "Event streaming unsupported")
		return
	}
	if s.streamSlots != nil {
		select {
		case s.streamSlots <- struct{}{}:
			defer func() { <-s.streamSlots }()
		default:
			writeFail(w, "Event stream limit reached")
			return
		}
	}
	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Accel-Buffering", "no")

	rc := http.NewResponseController(w)
	write := func(body string) bool {
		// Best effort: a writer without deadline support (tests) still
		// streams; the server's global WriteTimeout stays the backstop.
		_ = rc.SetWriteDeadline(time.Now().Add(eventWriteTimeout))
		if _, err := fmt.Fprint(w, body); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	// Subscribe before the snapshot leaves the socket: a client that reacts to
	// the first frame immediately must not race the subscription and lose the
	// next event. Frames published meanwhile queue in the subscriber buffer.
	var sub *events.Sub
	if s.hub != nil {
		sub = s.hub.Subscribe()
		defer s.hub.Unsubscribe(sub)
	}

	snap, err := eventsSnapshot()
	if err != nil {
		writeFail(w, "Event snapshot unavailable")
		return
	}
	raw, _ := json.Marshal(snap)
	snapBody, _ := json.Marshal(sseFrame{Data: raw})
	if !write("event: snapshot\ndata: " + string(snapBody) + "\n\n") {
		return
	}

	if sub == nil {
		// Without a hub (tests, odd embeds) the snapshot IS the stream.
		return
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-sub.C():
			if !ok {
				return
			}
			if p.Kind == "heartbeat" {
				if !write(": ping\n\n") {
					return
				}
				continue
			}
			body, err := json.Marshal(sseFrame{Revision: p.Revision, Data: p.Data})
			if err != nil {
				continue
			}
			if !write("event: " + p.Kind + "\ndata: " + string(body) + "\n\n") {
				return
			}
		}
	}
}
