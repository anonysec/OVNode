// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pairing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ovnode/internal/fsx"
)

const leaseSeconds = 30 * 60

func pairingPath() string {
	return filepath.Join(fsx.OVNodeDir(), "state", "pairing.json")
}

// Enforce applies the lease; returns error if refused.
func Enforce(panelID string) error {
	path := pairingPath()
	now := float64(time.Now().Unix())
	data, err := os.ReadFile(path)
	var rec *struct {
		PanelID  string  `json:"panel_id"`
		LastSeen float64 `json:"last_seen"`
	}
	if err != nil {
		if os.IsNotExist(err) {
			// no pairing file yet: unpaired
		} else {
			return fmt.Errorf("pairing file unreadable: %w", err)
		}
	} else {
		var r struct {
			PanelID  string  `json:"panel_id"`
			LastSeen float64 `json:"last_seen"`
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
	os.MkdirAll(filepath.Dir(path), 0o755)
	b, _ := json.Marshal(map[string]any{"panel_id": panelID, "last_seen": now})
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pairing-*")
	if err != nil {
		return err
	}
	tmp.Write(b)
	tmp.Close()
	os.Chmod(tmp.Name(), 0o600)
	return os.Rename(tmp.Name(), path)
}
