// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package settings

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ovnode/internal/fsx"
)

// LimitPolicy decides what the client-connect hook does when a user with more
// than one allowed device reaches the session limit.
type LimitPolicy string

const (
	// LimitStrict refuses the connection at the limit.
	LimitStrict LimitPolicy = "strict"
	// LimitReserve admits one temporary session for a reconnect. The reaper
	// removes a persistent extra after a grace.
	LimitReserve LimitPolicy = "reserve"
	// LimitTakeover kills one existing session and admits the new connection.
	LimitTakeover LimitPolicy = "takeover"
)

// NormalizeLimitPolicy accepts the panel spellings and the empty default.
func NormalizeLimitPolicy(value string) (LimitPolicy, error) {
	switch LimitPolicy(strings.ToLower(strings.TrimSpace(value))) {
	case "", LimitReserve:
		return LimitReserve, nil
	case LimitStrict:
		return LimitStrict, nil
	case LimitTakeover:
		return LimitTakeover, nil
	default:
		return LimitReserve, fmt.Errorf("limit policy must be strict, reserve or takeover")
	}
}

// LimitPolicyPath is the policy file. It lives beside the node state, not in
// server.json, so older nodes can still parse their own settings after a
// rollback.
func LimitPolicyPath() string {
	return filepath.Join(fsx.OVNodeDir(), "limit-policy")
}

// LoadLimitPolicy returns the configured policy. A missing file means the
// reconnect-friendly default.
func LoadLimitPolicy() (LimitPolicy, error) {
	data, err := os.ReadFile(LimitPolicyPath())
	if os.IsNotExist(err) {
		return LimitReserve, nil
	}
	if err != nil {
		return LimitReserve, err
	}
	return NormalizeLimitPolicy(string(data))
}

// SaveLimitPolicy validates and writes the policy atomically.
func SaveLimitPolicy(policy LimitPolicy) error {
	normalized, err := NormalizeLimitPolicy(string(policy))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(LimitPolicyPath()), 0o750); err != nil {
		return err
	}
	if err := fsx.WriteFileAtomic(LimitPolicyPath(), []byte(string(normalized)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Chmod(LimitPolicyPath(), 0o644)
}
