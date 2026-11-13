// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"ovnode/internal/config"
	"ovnode/internal/ovpn"
	"ovnode/internal/store"
)

// liveVirtualAddresses merges every configured protocol. A missing file
// means that protocol is not running; a torn one means keep everything.
func liveVirtualAddresses(override string) (map[string]bool, bool) {
	files := ovpn.StatusFiles()
	if override != "" && !slices.Contains(files, override) {
		files = []string{override}
	}
	live := map[string]bool{}
	for _, file := range files {
		snap, err := ovpn.ReadStatusSnapshot(file)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, false
		}
		for _, s := range snap.Sessions {
			live[s.VirtualAddress] = true
		}
	}
	return live, true
}

// PurgeStale removes session markers that are older than the TTL and whose
// pool address is no longer in the live status file.
//
// An incomplete status snapshot proves nothing: keep every marker rather
// than deleting a live session's accounting identity from a torn read.
// Only the session directory is touched — never user state or profiles.
func PurgeStale(cfg config.Hook) int {
	now := time.Now().Unix()
	live, ok := liveVirtualAddresses(cfg.StatusFile)
	if !ok {
		// A torn/incomplete snapshot proves nothing: keep every marker.
		summary, _ := json.Marshal(struct {
			Removed int `json:"removed"`
			Kept    int `json:"kept"`
			Scanned int `json:"scanned"`
		}{0, 0, 0})
		fmt.Println(string(summary))
		return 0
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
