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

// Enforce applies the lease; returns error if refused.
func Enforce(panelID string) error {
	enforceMu.Lock()
	defer enforceMu.Unlock()

	path := pairingPath()
	dir := filepath.Dir(path)
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

	now := time.Now().Unix()
	data, err := os.ReadFile(path)
	var rec *struct {
		PanelID  string `json:"panel_id"`
		LastSeen int64  `json:"last_seen"`
	}
	if err != nil {
		if os.IsNotExist(err) {
			// no pairing file yet: unpaired
		} else {
			return fmt.Errorf("pairing file unreadable: %w", err)
		}
	} else {
		var r struct {
			PanelID  string `json:"panel_id"`
			LastSeen int64  `json:"last_seen"`
		}
		if uerr := json.Unmarshal(data, &r); uerr != nil {
			return fmt.Errorf("pairing file corrupt: %w", uerr)
		} else if r.PanelID != "" {
			rec = &r
		} else {
			// empty/unpaired file
		}
	}
	if panelID == "" {
		if rec != nil {
			return os.ErrPermission
		}
		return nil
	}
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
	return nil
}
