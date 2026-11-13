// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"path/filepath"
	"testing"
	"time"

	"ovnode/internal/store"
)

// Marker names are <CN>.<pool>, and a dotted CN is valid, so "a" must not
// count "a.b"'s fresh marker as its own.
func TestFreshMarkerCountIgnoresLongerCN(t *testing.T) {
	tr := newTree(t)
	path := filepath.Join(tr.sessions, "a.b.10.8.0.2")
	if err := store.WriteMarker(path, store.Marker{
		CommonName: "a.b", PoolIP: "10.8.0.2",
		Created: time.Now().Unix(), SessionID: "a.b.10.8.0.2.1",
	}); err != nil {
		t.Fatal(err)
	}
	if got := freshMarkerCount(tr.config(), "a", nil, "a.10.8.0.9"); got != 0 {
		t.Fatalf("freshMarkerCount = %d, want 0 for another CN", got)
	}
}
