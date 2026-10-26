// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package logging

import (
	"strings"
	"testing"
)

// TestRecentFiltersByLevel covers the level filter of the log route.
//
// The panel asks for WARNING by default: a fresh node must not drown the
// operator in INFO records.
func TestRecentFiltersByLevel(t *testing.T) {
	Info("an info record")
	Warn("a warning record")
	Error("an error record")

	records := Recent("WARNING", 10)
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	for _, r := range records {
		if r.LevelNo < LevelNo("WARNING") {
			t.Fatalf("the record %q is below the filter", r.Message)
		}
	}
	if !strings.Contains(records[1].Message, "an error record") {
		t.Fatalf("the last record is %q, want the error", records[1].Message)
	}
}

// TestRecentKeepsTheNewestRecords covers the limit.
func TestRecentKeepsTheNewestRecords(t *testing.T) {
	for i := 0; i < 5; i++ {
		Info("record %d", i)
	}
	records := Recent("DEBUG", 2)
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	if !strings.Contains(records[1].Message, "record 4") {
		t.Fatalf("the last record is %q, want the newest one", records[1].Message)
	}
}

// TestRecordCarriesThePanelKeys covers the keys the panel reads inside a
// log record.
func TestRecordCarriesThePanelKeys(t *testing.T) {
	Warn("a warning with a place")
	records := Recent("WARNING", 1)
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	r := records[0]
	if r.Level != "WARNING" || r.Time == "" || r.Message == "" || r.Where == "" {
		t.Fatalf("the record is incomplete: %+v", r)
	}
	if !strings.Contains(r.Where, ".go:") {
		t.Fatalf("where = %q, want the caller of the log call", r.Where)
	}
}

// TestStatsCountsTheLastHour covers the error counters the panel's node
// badge reads.
func TestStatsCountsTheLastHour(t *testing.T) {
	Warn("a warning")
	Error("an error")
	errs, warnings, lastError := Stats()
	if errs < 1 {
		t.Fatalf("errors_1h = %d, want at least 1", errs)
	}
	if warnings < 1 {
		t.Fatalf("warnings_1h = %d, want at least 1", warnings)
	}
	if !strings.Contains(lastError, "an error") {
		t.Fatalf("last_error = %q, want the newest error", lastError)
	}
}

// TestRingIsBounded covers the size of the buffer: it must not grow without
// limit on a busy node.
func TestRingIsBounded(t *testing.T) {
	for i := 0; i < RingSize+50; i++ {
		Info("filler %d", i)
	}
	records := Recent("DEBUG", RingSize)
	if len(records) > RingSize {
		t.Fatalf("records = %d, want at most %d", len(records), RingSize)
	}
}
