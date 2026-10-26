// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package store is the slice of the on-disk node store the OpenVPN hooks
// need: the per-user enforcement state, the session markers and the usage
// accumulator.
//
// The tree layout is unchanged from the Python agent — the Go hook reads the
// same files the bash hook reads, so a node can switch implementations
// without a migration.
package store

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// UserState is the enforcement state of one user.
//
// LimitSet is false when the user has no limit of its own; the caller then
// applies its default. The distinction matters: a user with limit=0 is
// unlimited, which is not the same as a user with no state.
type UserState struct {
	Limit    int
	LimitSet bool
	Disabled bool
}

// ReadUserState reads <usersDir>/<cn>/state.
//
// The merged `state` file is the authority. The legacy split files (`limit`
// value, `disabled` existence marker) are honored per field, so pre-merge
// installs and backups keep working with no migration step.
//
// Values are compared exactly, like the bash hook: the file is written by
// the store as "limit=2" and never with stray whitespace.
func ReadUserState(usersDir, cn string) UserState {
	st := UserState{}
	dir := filepath.Join(usersDir, cn)
	// disabledSet records that the merged file spoke about `disabled` at all.
	// A merged file that says disabled=0 is authoritative: consulting the
	// legacy marker afterwards would re-disable a user the merge re-enabled.
	disabledSet := false
	if data, err := os.ReadFile(filepath.Join(dir, "state")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch k {
			case "limit":
				if n, err := strconv.Atoi(v); err == nil && isDigits(v) {
					st.Limit = n
					st.LimitSet = true
				}
			case "disabled":
				disabledSet = true
				if v == "1" {
					st.Disabled = true
				}
			}
		}
	}
	if !disabledSet {
		if _, err := os.Stat(filepath.Join(dir, "disabled")); err == nil {
			st.Disabled = true
		}
	}
	if !st.LimitSet {
		if raw, err := os.ReadFile(filepath.Join(dir, "limit")); err == nil {
			// Only the first line counts, and only its digits: a limit
			// file is a bare number, and anything else is ignored.
			line := string(raw)
			if i := strings.IndexAny(line, "\r\n"); i >= 0 {
				line = line[:i]
			}
			if digits := digitsOnly(string(line)); digits != "" {
				if n, err := strconv.Atoi(digits); err == nil {
					st.Limit = n
					st.LimitSet = true
				}
			}
		}
	}
	return st
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// Lock runs fn while holding an exclusive flock on path.
//
// The lock file is per-CN, so two sessions of the same user serialize while
// different users never block each other. A global lock would turn a
// reconnect storm into a queue.
func Lock(path string, fn func() error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
