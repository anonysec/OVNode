// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"strconv"

	"ovnode/internal/ovpn"
)

// handleUsage answers the per-user traffic counters.
func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	usage, err := ovpn.UsersUsage()
	if err != nil {
		writeOK(w, "Usage sample unavailable", map[string]any{
			"usage_available": false,
			"sample":          "unavailable",
			"users":           map[string]uint64{},
			"sessions":        map[string]any{},
			"totals":          map[string]uint64{},
			"totals_epochs":   map[string]string{},
			"error":           err.Error(),
		})
		return
	}
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
	hours := 8
	if raw := r.URL.Query().Get("hours"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			hours = n
		}
	}
	writeOK(w, "Session diagnostics retrieved successfully",
		ovpn.UserDiagnostics(r.URL.Query().Get("common_name"), hours))
}
