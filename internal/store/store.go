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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"ovnode/internal/fsx"
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
	Name     string
	NameSet  bool
}

// ReadUserState reads <usersDir>/<cn>/state.
//
// The merged `state` file is the authority. The legacy split files (`limit`
// value, `disabled` existence marker) are honored per field, so pre-merge
// installs and backups keep working with no migration step.
//
// Values are compared exactly, like the bash hook: the file is written by
// the store as "limit=2" and never with stray whitespace.
func ReadUserState(usersDir, cn string) (UserState, error) {
	st := UserState{}
	dir, err := UserDir(usersDir, cn)
	if err != nil {
		return UserState{}, err
	}
	if _, err := os.ReadDir(dir); err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return UserState{}, err
	}
	// disabledSet records that the merged file spoke about `disabled` at all.
	// A merged file that says disabled=0 is authoritative: consulting the
	// legacy marker afterwards would re-disable a user the merge re-enabled.
	disabledSet := false
	statePath := filepath.Join(dir, "state")
	if data, err := readPolicyFile(statePath); err == nil {
		seen := map[string]bool{}
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok || seen[k] {
				return UserState{}, fmt.Errorf("corrupt policy %s", statePath)
			}
			seen[k] = true
			switch k {
			case "limit":
				n, err := strconv.Atoi(v)
				if err != nil || !isDigits(v) {
					return UserState{}, fmt.Errorf("corrupt policy limit in %s", statePath)
				}
				st.Limit = n
				st.LimitSet = true
			case "disabled":
				if v != "0" && v != "1" {
					return UserState{}, fmt.Errorf("corrupt policy disabled flag in %s", statePath)
				}
				disabledSet = true
				st.Disabled = v == "1"
			case "name":
				if err := validateName(v); err != nil {
					return UserState{}, fmt.Errorf("corrupt policy name in %s: %w", statePath, err)
				}
				st.Name, st.NameSet = v, true
			default:
				return UserState{}, fmt.Errorf("unknown policy field in %s", statePath)
			}
		}
		if len(seen) == 0 {
			return UserState{}, fmt.Errorf("empty policy %s", statePath)
		}
	} else if !os.IsNotExist(err) {
		return UserState{}, err
	}
	if !disabledSet {
		if _, err := readPolicyFile(filepath.Join(dir, "disabled")); err == nil {
			st.Disabled = true
		} else if !os.IsNotExist(err) {
			return UserState{}, err
		}
	}
	if !st.LimitSet {
		if raw, err := readPolicyFile(filepath.Join(dir, "limit")); err == nil {
			line := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
			n, err := strconv.Atoi(line)
			if err != nil || !isDigits(line) {
				return UserState{}, fmt.Errorf("corrupt legacy limit in %s", dir)
			}
			st.Limit = n
			st.LimitSet = true
		} else if !os.IsNotExist(err) {
			return UserState{}, err
		}
	}
	return st, nil
}

func readPolicyFile(path string) ([]byte, error) {
	f, err := fsx.OpenFileNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
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

// Lock runs fn while holding an exclusive flock on path.
//
// The lock file is per-CN, so two sessions of the same user serialize while
// different users never block each other. A global lock would turn a
// reconnect storm into a queue.
func Lock(path string, perm os.FileMode, fn func() error) error {
	f, err := fsx.OpenFileNoFollow(path, os.O_CREATE|os.O_RDWR, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != perm {
		if err := f.Chmod(perm); err != nil {
			return err
		}
	}
	return fn()
}
