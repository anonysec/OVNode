// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// RingSize is the number of records the buffer keeps.
//
// The Python agent kept 500 (backend/logger.py). Both consumers are
// ring-bounded: the panel's log tab shows the tail, and the error counters
// in /sync/status are "errors in the last hour" over the same buffer.
const RingSize = 500

// Record is one log line in the shape the panel reads it.
type Record struct {
	TS      float64 `json:"ts"`
	Time    string  `json:"time"`
	Level   string  `json:"level"`
	LevelNo int     `json:"levelno"`
	Logger  string  `json:"logger"`
	Where   string  `json:"where"`
	Message string  `json:"message"`
}

// levelNo maps a level name to its number. An unknown name is a WARNING:
// the panel's default filter is WARNING, and a level the node cannot read
// must not silently hide the record.
func levelNo(name string) int {
	switch name {
	case "DEBUG":
		return 10
	case "INFO":
		return 20
	case "WARNING":
		return 30
	case "ERROR":
		return 40
	}
	return 30
}

// LevelNo returns the numeric level of a name (WARNING for unknown names).
func LevelNo(name string) int { return levelNo(name) }

type ring struct {
	mu      sync.Mutex
	records []Record
}

var buffer = &ring{records: make([]Record, 0, RingSize)}

func (r *ring) add(rec Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec)
	if len(r.records) > RingSize {
		r.records = r.records[len(r.records)-RingSize:]
	}
}

// Log records one line in the ring buffer and on stderr.
//
// stderr is the operator's copy, the ring is the panel's. The rotating file
// sink the Python agent had (data/app.log) belongs to the installer, not to
// the agent.
func Log(level, format string, args ...any) {
	emit(level, 2, format, args...)
}

// Info records an informational line.
func Info(format string, args ...any) { emit("INFO", 2, format, args...) }

// Warn records a warning line.
func Warn(format string, args ...any) { emit("WARNING", 2, format, args...) }

// Error records an error line.
func Error(format string, args ...any) { emit("ERROR", 2, format, args...) }

// emit writes the record.
//
// skip is the number of stack frames to ascend, so the record names the
// caller of the log call and not this file.
func emit(level string, skip int, format string, args ...any) {
	where := "?"
	if _, file, line, ok := runtime.Caller(skip); ok {
		where = fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}
	message := fmt.Sprintf(format, args...)
	now := time.Now()
	buffer.add(Record{
		TS:      float64(now.UnixNano()) / 1e9,
		Time:    now.Format("2006-01-02 15:04:05"),
		Level:   level,
		LevelNo: levelNo(level),
		Logger:  "ovnode",
		Where:   where,
		Message: message,
	})
	fmt.Fprintf(os.Stderr, "%s %-7s ovnode %s — %s\n",
		now.Format("2006-01-02 15:04:05"), level, where, message)
}

// Recent returns the records at or above minLevel, newest last.
//
// The order matches the Python agent: the panel renders the list as it came.
func Recent(minLevel string, limit int) []Record {
	if limit < 1 {
		limit = 1
	}
	if limit > RingSize {
		limit = RingSize
	}
	threshold := levelNo(minLevel)
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	out := make([]Record, 0, len(buffer.records))
	for _, r := range buffer.records {
		if r.LevelNo >= threshold {
			out = append(out, r)
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Stats counts the last hour's errors and warnings and returns the newest
// error message. The counters feed the panel's node badge.
func Stats() (errors int, warnings int, lastError string) {
	cutoff := float64(time.Now().UnixNano())/1e9 - 3600
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	for _, r := range buffer.records {
		if r.TS < cutoff {
			continue
		}
		switch {
		case r.LevelNo >= levelNo("ERROR"):
			errors++
			lastError = r.Time + " " + r.Message
		case r.LevelNo >= levelNo("WARNING"):
			warnings++
		}
	}
	return errors, warnings, lastError
}
