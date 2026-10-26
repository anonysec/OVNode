// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"os"
	"path/filepath"

	"ovnode/internal/fsx"
	"strconv"
	"strings"
)

// BankUsage adds a finished session's byte counters to the user's
// accumulator and returns the new total.
//
// OpenVPN exposes bytes_received/bytes_sent only at disconnect, so without
// this the traffic of a completed session would be lost between status-file
// polls. The accumulator is written under its own per-CN lock and through a
// temporary file, so a connect storm is never head-of-line blocked behind
// accounting and two simultaneous disconnects cannot lose an update.
func BankUsage(usageDir, safeCN string, delta uint64) (uint64, bool) {
	if delta == 0 {
		return 0, false
	}
	dirInfo, err := os.Stat(usageDir)
	if err != nil || !dirInfo.IsDir() {
		return 0, false
	}
	usageFile := filepath.Join(usageDir, safeCN)
	var total uint64
	err = Lock(filepath.Join(usageDir, ".lock."+safeCN), func() error {
		old := uint64(0)
		if raw, err := os.ReadFile(usageFile); err == nil {
			if n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); err == nil {
				old = n
			}
		}
		total = old + delta
		return fsx.WriteFileAtomic(usageFile, []byte(strconv.FormatUint(total, 10)+"\n"), 0o644)
	})
	if err != nil {
		return 0, false
	}
	return total, true
}
