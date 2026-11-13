// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package ovpn holds the OpenVPN runtime helpers the hooks need.
package ovpn

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Session is one connected client as seen in the status file.
//
// The stable identifiers are the virtual address (the VPN pool IP, unique
// per session under duplicate-cn) and the client id (the management CID) —
// not the real IP:port, which changes on every reconnect.
type Session struct {
	CommonName     string
	RealAddress    string
	TrustedIP      string
	TrustedPort    string
	VirtualAddress string
	BytesReceived  uint64
	BytesSent      uint64
	ClientID       string
	ConnectedAt    int64
	Protocol       string
}

// defaultColumns are the OpenVPN >= 2.4 CLIENT_LIST column positions, used
// when the status file carries no HEADER line.
var defaultColumns = map[string]int{
	"Common Name":              1,
	"Real Address":             2,
	"Virtual Address":          3,
	"Bytes Received":           5,
	"Bytes Sent":               6,
	"Client ID":                10,
	"Connected Since (time_t)": 8,
}

// columnMap resolves column names from a HEADER line.
func columnMap(headerParts []string) map[string]int {
	columns := copyDefaultColumns()
	for idx, name := range headerParts[2:] {
		if _, ok := columns[name]; ok {
			columns[name] = idx + 1
		}
	}
	return columns
}

// parseStatus scans a status stream. Columns are built once per header.
func parseStatus(r io.Reader) (StatusSnapshot, error) {
	columns := copyDefaultColumns()
	snap := StatusSnapshot{Sessions: []Session{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		delim := "\t"
		if !strings.Contains(line, "\t") {
			delim = ","
		}
		parts := strings.Split(line, delim)
		if strings.HasPrefix(line, "HEADER") && strings.Contains(line, "CLIENT_LIST") {
			columns = columnMap(parts)
			continue
		}
		if strings.HasPrefix(line, "TIME") {
			if len(parts) >= 3 {
				if n, err := strconv.ParseInt(strings.TrimSpace(parts[len(parts)-1]), 10, 64); err == nil {
					snap.UpdatedAt = n
				}
			}
			continue
		}
		if !strings.HasPrefix(line, "CLIENT_LIST") {
			if strings.TrimSpace(line) == "END" {
				snap.Complete = true
			}
			continue
		}
		cn := field(parts, columns["Common Name"])
		if cn == "" || cn == "Common Name" {
			continue
		}
		real := field(parts, columns["Real Address"])
		ip, port := splitRealAddress(real)
		snap.Sessions = append(snap.Sessions, Session{
			CommonName:     cn,
			RealAddress:    real,
			TrustedIP:      ip,
			TrustedPort:    port,
			VirtualAddress: field(parts, columns["Virtual Address"]),
			BytesReceived:  clampUint64(number(field(parts, columns["Bytes Received"]))),
			BytesSent:      clampUint64(number(field(parts, columns["Bytes Sent"]))),
			ClientID:       field(parts, columns["Client ID"]),
			ConnectedAt:    connectedAt(field(parts, columns["Connected Since (time_t)"])),
		})
	}
	if err := sc.Err(); err != nil {
		return StatusSnapshot{}, err
	}
	return snap, nil
}

// statusRetryPause is the re-read pause when OpenVPN is mid-rewrite. A var
// so tests do not sleep.
var statusRetryPause = 50 * time.Millisecond

// ParseSessions reads the status file and returns one Session per client.
//
// OpenVPN truncates and rewrites the file in place every few seconds. A read
// in that window sees an empty or partial list, which admission would take
// for "no live sessions"; retry once instead.
func ParseSessions(path string) []Session {
	var last []Session
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		snap, err := parseStatus(f)
		_ = f.Close()
		if err != nil {
			return last
		}
		proto := protocolFromStatusPath(path)
		for i := range snap.Sessions {
			snap.Sessions[i].Protocol = proto
		}
		last = snap.Sessions
		if snap.Complete {
			return last
		}
		if attempt == 0 {
			time.Sleep(statusRetryPause)
		}
	}
	return last
}

// protocolFromStatusPath recovers the transport from the per-protocol status
// directory (server/udp or server/tcp). An overridden status file can live
// anywhere, so the field stays empty and callers fall back to every socket.
func protocolFromStatusPath(path string) string {
	dir := filepath.Base(filepath.Dir(path))
	if dir == "udp" || dir == "tcp" {
		return dir
	}
	return ""
}

// SessionsForCN returns the live sessions of one common name.
func SessionsForCN(path, cn string) []Session {
	var out []Session
	for _, s := range ParseSessions(path) {
		if s.CommonName == cn {
			out = append(out, s)
		}
	}
	return out
}

func copyDefaultColumns() map[string]int {
	columns := make(map[string]int, len(defaultColumns))
	for k, v := range defaultColumns {
		columns[k] = v
	}
	return columns
}

func number(value string) uint64 {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func clampUint64(n uint64) uint64 {
	if n > math.MaxInt64 {
		return math.MaxInt64
	}
	return n
}

// connectedAt parses ConnectedAt via ParseInt (no int64(number(...)) conversion).
func connectedAt(value string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func field(parts []string, idx int) string {
	if idx < 0 || idx >= len(parts) {
		return ""
	}
	return strings.TrimSpace(parts[idx])
}

// splitRealAddress splits "ip:port" (IPv6-bracket aware) into its parts.
func splitRealAddress(real string) (string, string) {
	if real == "" {
		return "", ""
	}
	if i := strings.LastIndex(real, ":"); i >= 0 {
		return strings.Trim(real[:i], "[]"), real[i+1:]
	}
	return real, ""
}

// StatusSnapshot is a parsed OpenVPN status file with validity info.
type StatusSnapshot struct {
	Sessions  []Session
	UpdatedAt int64
	Complete  bool
}

// ReadStatusSnapshot reads the status file and validates the END marker.
func ReadStatusSnapshot(path string) (StatusSnapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return StatusSnapshot{}, err
	}
	defer f.Close()
	snap, err := parseStatus(f)
	if err != nil {
		return StatusSnapshot{}, err
	}
	if !snap.Complete {
		return snap, fmt.Errorf("incomplete status snapshot")
	}
	return snap, nil
}
