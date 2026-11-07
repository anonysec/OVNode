// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"fmt"
	"os"
	"path/filepath"
)

// BankUsage adds delta to a CN's v2 total without touching session offsets.
// It never rewrites a v2/invalid file as a legacy digit string: an unreadable
// counter is an error, not a silent zero. Preferred accounting is
// RecordSessionUsage; BankUsage remains for callers with only a delta.
func BankUsage(usageDir, safeCN string, delta uint64) (uint64, bool) {
	safe, err := SafeCN(safeCN)
	if err != nil {
		return 0, false
	}
	if delta == 0 {
		return 0, false
	}
	if err := os.MkdirAll(usageDir, 0o755); err != nil {
		return 0, false
	}
	var total uint64
	err = Lock(filepath.Join(usageDir, ".lock."+safe), 0o660, func() error {
		st, err := ReadUsageState(usageDir, safe)
		if err != nil {
			return err
		}
		if delta > 0 {
			if st.Total+delta < st.Total {
				return fmt.Errorf("counter overflow for %q", safeCN)
			}
			st.Total += delta
		}
		if st.Version != counterVersion {
			st.Version = counterVersion
			if st.Epoch == "" {
				st.Epoch = newEpoch()
			}
		}
		if st.Sessions == nil {
			st.Sessions = map[string]UsageSession{}
		}
		if err := writeUsageState(usageDir, safe, st); err != nil {
			return err
		}
		InvalidateUsageCache()
		total = st.Total
		return nil
	})
	if err != nil {
		return 0, false
	}
	return total, true
}
