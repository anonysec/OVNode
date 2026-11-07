// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package ovpn holds the OpenVPN runtime helpers the hooks need.
package ovpn

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
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

// columnMap resolves column name to index from a HEADER,CLIENT_LIST line.
//
// headerParts[0] is "HEADER" and [1] is "CLIENT_LIST"; a data row has no
// "HEADER" prefix, so a data field N corresponds to header index N + 1.
func columnMap(headerParts []string) map[string]int {
	columns := make(map[string]int, len(defaultColumns))
	for k, v := range defaultColumns {
		columns[k] = v
	}
	for idx, name := range headerParts[2:] {
		if _, ok := columns[name]; ok {
			columns[name] = idx + 1
		}
	}
	return columns
}

// ParseSessions reads the status file and returns one Session per client.
//
// The file is tab- or comma-delimited depending on the OpenVPN version, and
// the columns are resolved from the HEADER line when there is one — OpenVPN
// 2.3 lacked the Virtual IPv6 column that shifts every later field.
func ParseSessions(path string) []Session {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	columns := make(map[string]int, len(defaultColumns))
	for k, v := range defaultColumns {
		columns[k] = v
	}
	var out []Session
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		delim := "\t"
		if !strings.Contains(line, "\t") {
			delim = ","
		}
		if strings.HasPrefix(line, "HEADER") && strings.Contains(line, "CLIENT_LIST") {
			columns = columnMap(strings.Split(line, delim))
			continue
		}
		if !strings.HasPrefix(line, "CLIENT_LIST") {
			continue
		}
		parts := strings.Split(line, delim)
		cn := field(parts, columns["Common Name"])
		if cn == "" || cn == "Common Name" {
			continue
		}
		real := field(parts, columns["Real Address"])
		ip, port := splitRealAddress(real)
		out = append(out, Session{
			CommonName:     cn,
			RealAddress:    real,
			TrustedIP:      ip,
			TrustedPort:    port,
			VirtualAddress: field(parts, columns["Virtual Address"]),
			BytesReceived:  number(field(parts, columns["Bytes Received"])),
			BytesSent:      number(field(parts, columns["Bytes Sent"])),
			ClientID:       field(parts, columns["Client ID"]),
			ConnectedAt:    int64(number(field(parts, columns["Connected Since (time_t)"]))),
		})
	}
	return out
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

// LivePools returns the set of VPN pool addresses currently in use.
func LivePools(path string) map[string]bool {
	out := map[string]bool{}
	for _, s := range ParseSessions(path) {
		if s.VirtualAddress != "" {
			out[s.VirtualAddress] = true
		}
	}
	return out
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

func number(value string) uint64 {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return n
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

	columns := make(map[string]int, len(defaultColumns))
	for k, v := range defaultColumns {
		columns[k] = v
	}
	snap := StatusSnapshot{Sessions: []Session{}}
	complete := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		delim := "\t"
		if !strings.Contains(line, "\t") {
			delim = ","
		}
		if strings.HasPrefix(line, "HEADER") && strings.Contains(line, "CLIENT_LIST") {
			columns = columnMap(strings.Split(line, delim))
			continue
		}
		if strings.HasPrefix(line, "TIME") {
			parts := strings.Split(line, delim)
			// TIME <date> <time> <unix>  or  TIME\t<date time>\t<unix>
			if len(parts) >= 3 {
				if n, err := strconv.ParseInt(strings.TrimSpace(parts[len(parts)-1]), 10, 64); err == nil {
					snap.UpdatedAt = n
				}
			}
			continue
		}
		if strings.HasPrefix(line, "CLIENT_LIST") {
			parts := strings.Split(line, delim)
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
				BytesReceived:  number(field(parts, columns["Bytes Received"])),
				BytesSent:      number(field(parts, columns["Bytes Sent"])),
				ClientID:       field(parts, columns["Client ID"]),
				ConnectedAt:    int64(number(field(parts, columns["Connected Since (time_t)"]))),
			})
			continue
		}
		if strings.TrimSpace(line) == "END" {
			complete = true
		}
	}
	if err := sc.Err(); err != nil {
		return StatusSnapshot{}, err
	}
	snap.Complete = complete
	if !complete {
		return snap, fmt.Errorf("incomplete status snapshot")
	}
	return snap, nil
}
