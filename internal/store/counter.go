// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"ovnode/internal/fsx"
)

// UsageSession is one observed session inside a persisted counter.
type UsageSession struct {
	Bytes     uint64 `json:"bytes"`
	Closed    bool   `json:"closed"`
	MarkerKey string `json:"marker_key"`
}

// UsageState is the persisted v2 counter for one CN.
type UsageState struct {
	Version  int                     `json:"version"`
	Epoch    string                  `json:"epoch"`
	Total    uint64                  `json:"total"`
	Sessions map[string]UsageSession `json:"sessions"`
}

const counterVersion = 2

var epochCounter uint64

func newEpoch() string {
	n := atomic.AddUint64(&epochCounter, 1)
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), n)
}

// HasGeneration reports whether a session ID carries a v2 generation
// suffix ("<marker filename>.<16 hex>"), i.e. its marker persisted the
// exact hook connection start. Legacy IDs carry creation-time evidence
// only and are tolerated where exact evidence is unavailable.
func HasGeneration(sessionID string) bool {
	if i := strings.LastIndex(sessionID, "."); i > 0 {
		gen := sessionID[i+1:]
		return len(gen) == 16 && isHex(gen)
	}
	return false
}

// markerKeyOf derives the marker filename from an accounting session ID.
// Production IDs are "<marker filename>.<16 hex generation>"; anything else
// (legacy/test IDs) is its own key.
func markerKeyOf(sessionID string) string {
	if i := strings.LastIndex(sessionID, "."); i > 0 && HasGeneration(sessionID) {
		return sessionID[:i]
	}
	return sessionID
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return len(s) > 0
}

// ReadUsageState reads the persisted counter for one CN.
//
// A legacy unsigned-integer file is accepted as the starting total (version 0).
// Empty, corrupt, incomplete, or unknown-version files return an error rather
// than a zero total: they are unavailable, not a fresh epoch.
func ReadUsageState(usageDir, cn string) (UsageState, error) {
	safe, err := SafeCN(cn)
	if err != nil {
		return UsageState{}, err
	}
	_ = fsx.MkdirAllNoFollow(usageDir, 0o770)
	data, err := os.ReadFile(filepath.Join(usageDir, safe))
	if err != nil {
		if os.IsNotExist(err) {
			return UsageState{
				Version:  counterVersion,
				Epoch:    newEpoch(),
				Total:    0,
				Sessions: map[string]UsageSession{},
			}, nil
		}
		return UsageState{}, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return UsageState{}, fmt.Errorf("empty counter file for %q", cn)
	}
	if isAllDigits(trimmed) {
		n, err := strconv.ParseUint(trimmed, 10, 64)
		if err != nil {
			return UsageState{}, err
		}
		return UsageState{
			Version:  0,
			Epoch:    "",
			Total:    n,
			Sessions: map[string]UsageSession{},
		}, nil
	}
	// Strict v2 validation: unknown fields, a missing/empty epoch, a missing
	// sessions map, or a version other than 2 is unavailable, not zero.
	var raw struct {
		Version  *int                     `json:"version"`
		Epoch    *string                  `json:"epoch"`
		Total    *uint64                  `json:"total"`
		Sessions *map[string]UsageSession `json:"sessions"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return UsageState{}, err
	}
	if dec.More() {
		return UsageState{}, fmt.Errorf("trailing data in counter file for %q", cn)
	}
	if raw.Version == nil || *raw.Version != counterVersion {
		v := 0
		if raw.Version != nil {
			v = *raw.Version
		}
		return UsageState{}, fmt.Errorf("unknown counter version %d", v)
	}
	if raw.Epoch == nil || *raw.Epoch == "" || raw.Total == nil || raw.Sessions == nil {
		return UsageState{}, fmt.Errorf("incomplete v2 counter file for %q", cn)
	}
	st := UsageState{
		Version:  counterVersion,
		Epoch:    *raw.Epoch,
		Total:    *raw.Total,
		Sessions: *raw.Sessions,
	}
	for id, sess := range st.Sessions {
		if sess.MarkerKey == "" {
			sess.MarkerKey = markerKeyOf(id)
			st.Sessions[id] = sess
		}
	}
	return st, nil
}

func isAllDigits(s string) bool {
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

func writeUsageState(usageDir, safe string, st UsageState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(filepath.Join(usageDir, safe), data, 0o660)
}

// RecordSessionUsage records one observed byte total for a session and
// returns the updated state. Closed sessions reject stale observations.
// One atomic rename commits total, offsets, and receipt together.
func RecordSessionUsage(usageDir, cn, sessionID string, bytes uint64, closed bool) (UsageState, error) {
	safe, err := SafeCN(cn)
	if err != nil {
		return UsageState{}, err
	}
	if sessionID == "" {
		return UsageState{}, fmt.Errorf("empty session id")
	}
	if err := fsx.MkdirAllNoFollow(usageDir, 0o770); err != nil {
		return UsageState{}, err
	}
	var result UsageState
	err = Lock(filepath.Join(usageDir, ".lock."+safe), 0o660, func() error {
		st, err := ReadUsageState(usageDir, safe)
		if err != nil {
			return err
		}
		if st.Sessions == nil {
			st.Sessions = map[string]UsageSession{}
		}
		if st.Version != counterVersion {
			st.Version = counterVersion
			if st.Epoch == "" {
				st.Epoch = newEpoch()
			}
		}
		sess, ok := st.Sessions[sessionID]
		if !ok {
			sess = UsageSession{MarkerKey: markerKeyOf(sessionID)}
		}
		if !sess.Closed && bytes > sess.Bytes {
			delta := bytes - sess.Bytes
			if st.Total+delta < st.Total {
				return fmt.Errorf("counter overflow for %q", cn)
			}
			sess.Bytes = bytes
			st.Total += delta
		}
		if closed && !sess.Closed {
			sess.Closed = true
		}
		st.Sessions[sessionID] = sess
		if st.Epoch == "" {
			st.Epoch = newEpoch()
		}
		if err := writeUsageState(usageDir, safe, st); err != nil {
			return err
		}
		InvalidateUsageCache()
		result = st
		return nil
	})
	if err != nil {
		return UsageState{}, err
	}
	return result, nil
}

// PruneReceipts drops completed receipts whose generation is confirmed gone:
// the session ID is not in present (live session IDs plus marker session IDs
// still on disk). Live/unfinished offsets are always kept. Errors propagate.
func PruneReceipts(usageDir, cn string, present map[string]bool) error {
	safe, err := SafeCN(cn)
	if err != nil {
		return err
	}
	if err := fsx.MkdirAllNoFollow(usageDir, 0o770); err != nil {
		return err
	}
	return Lock(filepath.Join(usageDir, ".lock."+safe), 0o660, func() error {
		st, err := ReadUsageState(usageDir, safe)
		if err != nil {
			return err
		}
		changed := false
		for id, sess := range st.Sessions {
			if sess.Closed && !present[id] {
				delete(st.Sessions, id)
				changed = true
			}
		}
		if !changed {
			return nil
		}
		if err := writeUsageState(usageDir, safe, st); err != nil {
			return err
		}
		InvalidateUsageCache()
		return nil
	})
}

// ResetUsage zeroes the total, preserves live observed offsets, drops
// completed receipts, and rotates the epoch.
func ResetUsage(usageDir, cn string) error {
	safe, err := SafeCN(cn)
	if err != nil {
		return err
	}
	if err := fsx.MkdirAllNoFollow(usageDir, 0o770); err != nil {
		return err
	}
	return Lock(filepath.Join(usageDir, ".lock."+safe), 0o660, func() error {
		st, err := ReadUsageState(usageDir, safe)
		if err != nil {
			return err
		}
		if st.Sessions == nil {
			st.Sessions = map[string]UsageSession{}
		}
		for id, sess := range st.Sessions {
			if sess.Closed {
				delete(st.Sessions, id)
			}
		}
		st.Version = counterVersion
		st.Total = 0
		st.Epoch = newEpoch()
		if err := writeUsageState(usageDir, safe, st); err != nil {
			return err
		}
		InvalidateUsageCache()
		return nil
	})
}
