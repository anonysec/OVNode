// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package installer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// WriteUpdateState writes the update-state.json atomically.
func WriteUpdateState(path, phase, from, target, backup, identity string) error {
	data := map[string]any{
		"phase":         phase,
		"from_version":  from,
		"to_version":    target,
		"safety_backup": nil,
		"identity_sha":  nil,
		"updated_at":    time.Now().Unix(),
		"pid":           os.Getppid(),
	}
	if backup != "" {
		data["safety_backup"] = backup
	}
	if identity != "" {
		data["identity_sha"] = identity
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	os.MkdirAll(filepath.Dir(path), 0o755)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".update-state-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	tmp.Write(b)
	tmp.Close()
	os.Chmod(tmpName, 0o600)
	return os.Rename(tmpName, path)
}

// ReadUpdateState reads the update state file.
func ReadUpdateState(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// EnsureSyscall import guard
