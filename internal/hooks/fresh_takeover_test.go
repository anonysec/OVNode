// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"path/filepath"
	"testing"
	"time"

	"ovnode/internal/store"
)

// A second device can connect before the status file echoes the first. The
// marker carries the pool address, so the takeover still has a target.
func TestConnectLimitOneTargetsFreshMarker(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=0\n")
	setClientEnv(t, "u1", "10.8.0.11")

	path := filepath.Join(tr.sessions, "u1.10.8.0.2")
	if err := store.WriteMarker(path, store.Marker{
		CommonName: "u1", TrustedIP: "9.9.9.9", TrustedPort: "5001",
		PoolIP: "10.8.0.2", Created: time.Now().Unix(),
		SessionID: "u1.10.8.0.2.1", ConnectedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	var got []string
	prev := notifyKill
	notifyKill = func(cid, proto, cn, virtual, real string) error {
		got = append(got, cid+"|"+virtual)
		return nil
	}
	t.Cleanup(func() { notifyKill = prev })

	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect = %d, want 0", code)
	}
	if len(got) != 1 || got[0] != "|10.8.0.2" {
		t.Fatalf("queued kills = %v, want the marker's pool address", got)
	}
}
