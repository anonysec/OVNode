// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pairing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"ovnode/internal/fsx"
)

const leaseSeconds = 30 * 60

func pairingPath() string {
	return filepath.Join(fsx.OVNodeDir(), "state", "pairing.json")
}

var enforceMu sync.Mutex

type record struct {
	PanelID  string `json:"panel_id"`
	LastSeen int64  `json:"last_seen"`
}

var cache struct {
	path  string
	rec   *record
	mtime time.Time
	have  bool
}

// Enforce applies the lease; returns error if refused.
//
// The file is the source of truth, but the parsed record is cached in
// memory under enforceMu. A repeated call for the same panel inside 60
// seconds, with the on-disk mtime unchanged, touches no file at all.
func Enforce(panelID string) error {
	enforceMu.Lock()
	defer enforceMu.Unlock()

	path := pairingPath()
	dir := filepath.Dir(path)
	if cache.have && cache.path != path {
		cache.have = false
		cache.rec = nil
	}
	if cache.have && cache.path == path {
		if fi, err := os.Stat(path); err == nil {
			if !fi.ModTime().Equal(cache.mtime) {
				cache.have = false
			}
		} else if os.IsNotExist(err) {
			cache.have = false
			cache.rec = nil
		}
	}
	if cache.have && cache.path == path && cache.rec != nil && cache.rec.PanelID == panelID {
		now0 := time.Now().Unix()
		if panelID != "" && now0-cache.rec.LastSeen < 60 {
			return nil
		}
		if panelID == "" {
			return os.ErrPermission
		}
		// Re-read the file to get the latest last_seen, as the cache might be stale.
		fi, err := os.Stat(path)
		if err == nil && !fi.ModTime().Equal(cache.mtime) {
			cache.have = false
		}
		if cache.have {
			data, err := os.ReadFile(path)
			if err == nil {
				var r record
				if json.Unmarshal(data, &r) == nil && r.PanelID == panelID {
					cache.rec = &r
					cache.mtime = fi.ModTime()
				} else {
					cache.have = false
				}
			} else {
				cache.have = false
			}
		}
		if !cache.have || cache.rec == nil || cache.rec.PanelID != panelID {
			// Cache is stale or panelID changed, fall through to write.
		} else {
			now0 := time.Now().Unix()
			if now0-cache.rec.LastSeen < 60 {
				return nil
			}
			if now0-cache.rec.LastSeen > leaseSeconds {
				// Lease expired: fall through to the write.
			} else {
				// Same panel refreshing mid-lease: fall through to write.
			}
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	lockFile := path + ".lock"
	lf, err := os.OpenFile(lockFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)

	// Re-read under the lock: another process may have changed the file
	// since the cache check above.
	var rec *record
	if cache.have && cache.path == path && cache.rec != nil {
		rec = cache.rec
	} else {
		fi, err := os.Stat(path)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("pairing file unreadable: %w", err)
		}
		if err == nil {
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("pairing file unreadable: %w", err)
			}
			var r record
			if uerr := json.Unmarshal(data, &r); uerr != nil {
				return fmt.Errorf("pairing file corrupt: %w", uerr)
			} else if r.PanelID != "" {
				rec = &r
			}
			cache.path = path
			cache.rec = rec
			cache.mtime = fi.ModTime()
			cache.have = true
		} else {
			cache.path = path
			cache.rec = nil
			cache.have = true
			cache.mtime = time.Time{}
		}
	}
	if panelID == "" {
		if rec != nil {
			return os.ErrPermission
		}
		return nil
	}
	now := time.Now().Unix()
	if rec != nil && rec.PanelID != panelID {
		age := now - rec.LastSeen
		if age <= leaseSeconds {
			return os.ErrPermission
		}
	}
	if rec != nil && rec.PanelID == panelID && now-rec.LastSeen < 60 {
		return nil
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	b, _ := json.Marshal(map[string]any{"panel_id": panelID, "last_seen": now})
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pairing-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	_ = tmp.Close()
	_ = os.Chmod(tmpPath, 0o600)
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	renamed = true
	if fi, err := os.Stat(path); err == nil {
		cache.path = path
		cache.rec = &record{PanelID: panelID, LastSeen: now}
		cache.mtime = fi.ModTime()
		cache.have = true
	}
	return nil
}
