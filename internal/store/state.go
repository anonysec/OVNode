// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"fmt"
	"os"
	"path/filepath"

	"ovnode/internal/fsx"
	"strconv"
	"strings"
)

// WriteUserState merges limit and disabled into <usersDir>/<cn>/state.
//
// A nil field keeps its current value, so a caller that only changes the
// limit never clears the disabled flag. The legacy split files (a `limit`
// value file and a `disabled` existence marker) are removed once the merged
// file lands, so the tree converges on one format.
func WriteUserState(usersDir, cn string, limit *int, disabled *bool) error {
	dir, err := UserDir(usersDir, cn)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	current := ReadUserState(usersDir, cn)
	effective := current.Limit
	if !current.LimitSet {
		effective = 1
	}
	if limit != nil {
		effective = *limit
		if effective < 0 {
			effective = 0
		}
	}
	off := current.Disabled
	if disabled != nil {
		off = *disabled
	}
	body := fmt.Sprintf("limit=%d\ndisabled=%d\n", effective, boolInt(off))
	if err := fsx.WriteFileAtomic(filepath.Join(dir, "state"), []byte(body), 0o644); err != nil {
		return err
	}
	for _, legacy := range []string{"limit", "disabled"} {
		_ = os.Remove(filepath.Join(dir, legacy))
	}
	return nil
}

// SetLimit sets the max simultaneous logins for a user.
func SetLimit(usersDir, cn string, maxLogins int) error {
	return WriteUserState(usersDir, cn, &maxLogins, nil)
}

// SetDisabled activates or deactivates a user.
func SetDisabled(usersDir, cn string, disabled bool) error {
	return WriteUserState(usersDir, cn, nil, &disabled)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// NameMap returns cn → panel username for every user that has one.
//
// The map is cached: the panel pushes a name once and then only polls
// counters, so rebuilding it on every request would stat the whole users
// tree per poll.
func NameMap(usersDir string) map[string]string {
	if m, ok := NameCacheGet(usersDir); ok {
		return m
	}
	m := map[string]string{}
	for _, cn := range ListUsers(usersDir) {
		if name := ReadName(usersDir, cn); name != "" {
			m[cn] = name
		}
	}
	NameCacheSet(usersDir, m)
	return m
}

// CNForName is the reverse lookup: panel username → CN.
func CNForName(usersDir, name string) string {
	for cn, uname := range NameMap(usersDir) {
		if uname == name {
			return cn
		}
	}
	return ""
}

// AccumulatedUsage returns the bytes banked by a user's finished sessions.
//
// A corrupt bank file (undecodable or non-numeric) counts as 0 instead of
// failing: the panel poll must stay a 200.
func AccumulatedUsage(usageDir, cn string) uint64 {
	raw, err := os.ReadFile(filepath.Join(usageDir, cn))
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// AllAccumulatedUsage returns cn → banked bytes for every user with usage.
//
// The cache keeps a busy node from re-reading the whole usage directory on
// every panel poll.
func AllAccumulatedUsage(usageDir string) map[string]uint64 {
	if m, ok := UsageCacheGet(usageDir); ok {
		return m
	}
	out := map[string]uint64{}
	entries, err := os.ReadDir(usageDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		// `.lock.<cn>` is the store's own per-CN flock file, not a user.
		if e.IsDir() || strings.HasPrefix(e.Name(), ".lock.") {
			continue
		}
		if !fsx.StoreKeyRe.MatchString(e.Name()) {
			continue
		}
		if n := AccumulatedUsage(usageDir, e.Name()); n > 0 {
			out[e.Name()] = n
		}
	}
	UsageCacheSet(usageDir, out)
	return out
}

// ResetUsage removes a user's banked counter.
//
// The removal happens under the same lock the disconnect hook uses for its
// read-modify-write, so a concurrent hook cannot write the pre-reset total
// back and silently undo the reset.
func ResetUsage(usageDir, cn string) error {
	safe, err := SafeCN(cn)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(usageDir, 0o755); err != nil {
		return err
	}
	InvalidateUsageCache()
	return Lock(filepath.Join(usageDir, ".lock."+safe), func() error {
		if err := os.Remove(filepath.Join(usageDir, safe)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	})
}
