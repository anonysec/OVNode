// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package logging writes the hook event log.
//
// The line shape is a contract: the panel reads this file and classifies each
// line, so it stays "<epoch> [ovnode-mlogin] <message>". Losing a log line
// must never turn into a rejected client, so every write is best effort.
package logging

import (
	"fmt"
	"log/syslog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Tag marks every hook event line.
const Tag = "ovnode-mlogin"

// Event appends one line to the hook event file.
func Event(path, format string, args ...any) {
	if path == "" {
		return
	}
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	line := fmt.Sprintf("%d [%s] %s\n", time.Now().Unix(), Tag, fmt.Sprintf(format, args...))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

// Syslog writes one line to syslog under the hook tag.
//
// The disconnect hook logs here and the connect hook logs to the event file;
// the asymmetry is deliberate and predates the Go port: the panel reads the
// file, the operator reads the journal.
func Syslog(format string, args ...any) {
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_USER, Tag)
	if err != nil {
		return
	}
	defer w.Close()
	_ = w.Info(strings.TrimSpace(fmt.Sprintf(format, args...)))
}
