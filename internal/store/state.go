// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"fmt"
	"os"
	"path/filepath"

	"ovnode/internal/fsx"
	"strings"
)

// WriteUserState merges limit and disabled into <usersDir>/<cn>/state.
//
// A nil field keeps its current value, so a caller that only changes the
// limit never clears the disabled flag. One `state` file is the only format.
func WriteUserState(usersDir, cn string, limit *int, disabled *bool) error {
	return WriteUserPolicy(usersDir, cn, nil, limit, disabled)
}

func WriteUserPolicy(usersDir, cn string, name *string, limit *int, disabled *bool) error {
	if name != nil {
		if err := validateName(*name); err != nil {
			return err
		}
	}
	dir, err := UserDir(usersDir, cn)
	if err != nil {
		return err
	}
	if err := CreateUser(usersDir, cn); err != nil {
		return err
	}
	// Serialize read/merge/write across processes with a root-only state lock.
	return Lock(filepath.Join(dir, ".state.lock"), 0o600, func() error {
		current, err := ReadUserState(usersDir, cn)
		if err != nil {
			return err
		}
		if name != nil {
			current.Name, current.NameSet = *name, true
		}
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
		body := fmt.Sprintf("disabled=%d\n", boolInt(off))
		if current.LimitSet || limit != nil || disabled != nil || name == nil {
			body = fmt.Sprintf("limit=%d\n", effective) + body
		}
		if current.NameSet {
			body += "name=" + current.Name + "\n"
		}
		if err := fsx.WriteFileAtomic(filepath.Join(dir, "state"), []byte(body), 0o640); err != nil {
			return err
		}
		f, err := os.Open(dir)
		if err != nil {
			return err
		}
		err = f.Sync()
		f.Close()
		if err != nil {
			return err
		}
		InvalidateNameCache()
		return nil
	})
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

// AccumulatedUsage returns the persisted total for one CN.
func AccumulatedUsage(usageDir, cn string) uint64 {
	st, err := ReadUsageState(usageDir, cn)
	if err != nil {
		return 0
	}
	return st.Total
}

// AllAccumulatedUsage returns cn → persisted total for every user with usage.
//
// Authoritative accounting reads the persisted counter directly; the bank
// value cache is intentionally not consulted.
func AllAccumulatedUsage(usageDir string) map[string]uint64 {
	out := map[string]uint64{}
	entries, err := os.ReadDir(usageDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".lock.") {
			continue
		}
		if !fsx.StoreKeyRe.MatchString(e.Name()) {
			continue
		}
		if st, err := ReadUsageState(usageDir, e.Name()); err == nil {
			out[e.Name()] = st.Total
		}
	}
	return out
}
