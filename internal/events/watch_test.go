// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package events

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ovnode/internal/fsx"
	"ovnode/internal/ovpn"
	"ovnode/internal/pki"
	"ovnode/internal/store"
)

// watcherHub runs Watch with a 10 ms tick and returns the subscriber.
func watcherHub(t *testing.T) (*Hub, <-chan Payload, context.CancelFunc) {
	t.Helper()
	h := NewHub()
	sub := h.Subscribe()
	ctx, cancel := context.WithCancel(context.Background())
	go Watch(ctx, h, 10*time.Millisecond, func() (any, error) {
		return ovpn.UserDiagnostics("", 8), nil
	})
	return h, sub.C(), cancel
}

func writeStatus(t *testing.T, rows string) {
	t.Helper()
	body := "TIME\tfixture\t150\n" +
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\n" +
		rows + "END\n"
	if err := os.WriteFile(ovpn.StatusFile(), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func waitForKind(t *testing.T, ch <-chan Payload, kind string, dur time.Duration) Payload {
	t.Helper()
	deadline := time.After(dur)
	for {
		select {
		case p := <-ch:
			if p.Kind == kind {
				return p
			}
		case <-deadline:
			t.Fatalf("no %q payload within %s", kind, dur)
		}
	}
}

func TestWatcherPublishesOnStatusChange(t *testing.T) {
	_, ch, cancel := watcherHub(t)
	defer cancel()
	writeStatus(t, "CLIENT_LIST\t2\t198.51.100.2:2000\t10.66.0.2\t\t100\t50\tfixture\t100\tUNDEF\t1\n")
	p := waitForKind(t, ch, "sessions", 2*time.Second)
	if p.Revision == 0 {
		t.Fatal("sessions payload carried revision 0")
	}
}

func TestWatcherUsageTickShape(t *testing.T) {
	_, ch, cancel := watcherHub(t)
	defer cancel()
	if _, err := store.RecordSessionUsage(pki.UsageDir(), "2", "sess1", 4096, true); err != nil {
		t.Fatal(err)
	}
	p := waitForKind(t, ch, "usage", 3*time.Second)
	var body struct {
		Totals map[string]uint64 `json:"totals"`
	}
	if err := json.Unmarshal(p.Data, &body); err != nil {
		t.Fatalf("usage body: %v", err)
	}
	if body.Totals["2"] != 4096 {
		t.Fatalf("usage totals %v, want {2:4096}", body.Totals)
	}
}

func TestWatcherIdleDoesNothing(t *testing.T) {
	h := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writeStatus(t, "")
	go Watch(ctx, h, 5*time.Millisecond, func() (any, error) {
		t.Error("snapshot provider called while no consumer is attached")
		return nil, nil
	})
	time.Sleep(100 * time.Millisecond)
	if h.Count() != 0 {
		t.Fatal("unexpected subscriber")
	}
}

func TestWatcherSessionsDirChange(t *testing.T) {
	_, ch, cancel := watcherHub(t)
	defer cancel()
	writeStatus(t, "")
	if err := store.WriteMarker(filepath.Join(fsx.SessionsDir(), "2.10.66.0.2"), store.Marker{
		CommonName: "2", PoolIP: "10.66.0.2", SessionID: "2.10.66.0.2",
	}); err != nil {
		t.Fatal(err)
	}
	waitForKind(t, ch, "sessions", 2*time.Second)
}
