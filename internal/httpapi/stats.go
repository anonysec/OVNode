// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"strconv"

	"ovnode/internal/ovpn"
)

// handleUsage answers the per-user traffic counters.
//
// The panel's traffic collector resolves the keys by display name, so the
// totals are keyed by the name where the node knows it.
func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, false) {
		return
	}
	usage := ovpn.UsersUsage()
	users, _ := usage["users"].(map[string]uint64)
	if len(users) == 0 {
		writeOK(w, "No user is using it.", usage)
		return
	}
	writeOK(w, "Latest user usage received", usage)
}

// handleSessions answers the live sessions, the stale markers and the
// login-health counters.
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, false) {
		return
	}
	hours := 8
	if raw := r.URL.Query().Get("hours"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			hours = n
		}
	}
	writeOK(w, "Session diagnostics retrieved successfully",
		ovpn.UserDiagnostics(r.URL.Query().Get("common_name"), hours))
}
