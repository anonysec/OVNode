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
// An incomplete status snapshot proves nothing: keep every marker rather
// than deleting a live session's accounting identity from a torn read.
// Only the session directory is touched — never user state or profiles.
func PurgeStale(cfg config.Hook) int {
	now := time.Now().Unix()
	// A torn/incomplete snapshot proves nothing: keep every marker.
	snap, err := ovpn.ReadStatusSnapshot(cfg.StatusFile)
	if err != nil {
		summary, _ := json.Marshal(struct {
			Removed int `json:"removed"`
			Kept    int `json:"kept"`
			Scanned int `json:"scanned"`
		}{0, 0, 0})
		fmt.Println(string(summary))
		return 0
	}
	live := map[string]bool{}
	for _, s := range snap.Sessions {
		live[s.VirtualAddress] = true
	}

	entries, err := os.ReadDir(cfg.SessionsDir)
	if err != nil {
		entries = nil
	}
	scanned, removed, kept := 0, 0, 0
	affected := map[string]bool{}
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
			affected[marker.CommonName] = true
			fmt.Fprintf(os.Stderr, "removed stale marker %s (age=%ds)\n", name, age)
			continue
		}
		kept++
	}
	// Retire completed receipts of purged generations (confirmed marker
	// absence); live marker IDs are retained.
	if len(affected) > 0 {
		remaining, err := os.ReadDir(cfg.SessionsDir)
		if err == nil {
			present := map[string]map[string]bool{}
			for _, e := range remaining {
				if strings.HasPrefix(e.Name(), ".") || e.IsDir() {
					continue
				}
				if m, ok := store.ReadMarker(filepath.Join(cfg.SessionsDir, e.Name())); ok {
					if present[m.CommonName] == nil {
						present[m.CommonName] = map[string]bool{}
					}
					present[m.CommonName][m.SessionID] = true
					present[m.CommonName][e.Name()] = true
				}
			}
			for cn := range affected {
				_ = store.PruneReceipts(cfg.UsageDir, cn, present[cn])
			}
		}
	}

	summary, _ := json.Marshal(struct {
		Removed int `json:"removed"`
		Kept    int `json:"kept"`
		Scanned int `json:"scanned"`
	}{removed, kept, scanned})
	fmt.Println(string(summary))
	return 0
}
