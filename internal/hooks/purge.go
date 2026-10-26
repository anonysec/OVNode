// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ovnode/internal/config"
	"ovnode/internal/ovpn"
	"ovnode/internal/store"
)

// PurgeStale removes session markers that are older than the TTL and whose
// pool address is no longer in the live status file.
//
// A marker like that is a corpse left by a crashed daemon or a dropped
// disconnect hook. A marker whose pool address is still live stays, and so
// does a marker that cannot be parsed. Only the session directory is
// touched — never the user state or the profiles.
func PurgeStale(cfg config.Hook) int {
	now := time.Now().Unix()
	live := ovpn.LivePools(cfg.StatusFile)

	entries, err := os.ReadDir(cfg.SessionsDir)
	if err != nil {
		entries = nil
	}
	scanned, removed, kept := 0, 0, 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || e.IsDir() {
			continue
		}
		scanned++
		path := filepath.Join(cfg.SessionsDir, name)
		marker, ok := store.ReadMarker(path)
		if !ok {
			kept++
			continue
		}
		age := now - marker.Created
		if marker.Created > 0 && age > int64(cfg.SessionTTL) && !live[marker.PoolIP] {
			if err := os.Remove(path); err != nil {
				fmt.Fprintf(os.Stderr, "keep %s: remove failed: %v\n", name, err)
				kept++
				continue
			}
			removed++
			fmt.Fprintf(os.Stderr, "removed stale marker %s (age=%ds)\n", name, age)
			continue
		}
		kept++
	}

	summary, _ := json.Marshal(struct {
		Removed int `json:"removed"`
		Kept    int `json:"kept"`
		Scanned int `json:"scanned"`
	}{removed, kept, scanned})
	fmt.Println(string(summary))
	return 0
}
