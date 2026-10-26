// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"ovnode/internal/logging"
	"ovnode/internal/ovpn"
	"ovnode/internal/pki"
	"ovnode/internal/updater"
	"ovnode/internal/version"
)

// handleHealth is the Docker healthcheck probe: no auth, so the container
// can poll it.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeOK(w, "ok", map[string]any{"status": "ok"})
}

// handleStatus answers the panel's node poll.
//
// The panel reads cpu_usage, memory_usage and cert_expiry; the remaining
// keys are additive diagnostics, so the node's health is visible without
// SSH.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, false) {
		return
	}
	errors1h, warnings1h, lastError := logging.Stats()
	healthy := pki.Healthy()
	status := "running"
	if !healthy {
		status = "degraded"
	}
	writeOK(w, "Node status retrieved successfully", map[string]any{
		"status":          status,
		"version":         version.Version,
		"cpu_usage":       cpuUsage(),
		"memory_usage":    memoryUsage(),
		"openvpn_running": ovpn.OpenVPNIsRunning(),
		"uptime_seconds":  int(time.Since(s.started).Seconds()),
		"pki_healthy":     healthy,
		// The TLS certificate, so the panel can warn before the
		// connectivity breaks.
		"cert_expiry": pki.CertExpiry(s.CertFile),
		// The VPN PKI: a lapsed CA or server certificate silently kills
		// every client and the panel cannot see it otherwise.
		"ca_expiry":     pki.CertExpiry(pki.CACert()),
		"server_expiry": pki.CertExpiry(pki.ServerCert()),
		"errors_1h":     errors1h,
		"warnings_1h":   warnings1h,
		"last_error":    lastError,
	})
}

// handleLogs answers the panel's log viewer.
//
// The records come from the in-memory ring buffer the agent writes into, so
// a node that was never polled still has its own history.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, false) {
		return
	}
	level := r.URL.Query().Get("level")
	if level == "" {
		level = "WARNING"
	}
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			limit = n
		}
	}
	records := logging.Recent(level, limit)
	errors1h, warnings1h, lastError := logging.Stats()
	writeOK(w, fmt.Sprintf("%d log record(s)", len(records)), map[string]any{
		"records":     records,
		"last_error":  lastError,
		"errors_1h":   errors1h,
		"warnings_1h": warnings1h,
	})
}

// handleConfigGet answers the live endpoint settings, so the panel can
// detect a drift against what it last pushed.
func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, false) {
		return
	}
	writeOK(w, "Configuration retrieved successfully", ovpn.ReadConfig())
}

// handleConfigPost applies the endpoint settings the panel pushed.
//
// The data carries the applied change kind — restart_required (structural)
// against hot_reload (hot) — so the panel can sequence around a restart
// without re-deriving the diff itself.
func (s *Server) handleConfigPost(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, false) {
		return
	}
	var req ovpn.ChangeConfigRequest
	if err := decodeBody(r, &req); err != nil {
		writeFail(w, "Invalid configuration payload")
		return
	}
	if req.SetNewSetting != nil && !*req.SetNewSetting {
		writeOK(w, "No changes requested", nil)
		return
	}
	res := ovpn.ChangeConfigResult{}
	if !ovpn.ChangeConfig(req, &res) {
		writeFail(w, "Failed to change settings")
		return
	}
	logging.Info("configuration applied (restart_required=%t, hot_reload=%t)",
		res.RestartRequired, res.HotReload)
	writeOK(w, "Configuration updated successfully", map[string]any{
		"restart_required": res.RestartRequired,
		"hot_reload":       res.HotReload,
	})
}

// handleRestart restarts or reloads OpenVPN.
//
// The failure is reported inside the envelope, so a broken OpenVPN cannot
// take the API down with it.
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, true) {
		return
	}
	restarted := ovpn.RestartOpenVPN()
	running := ovpn.OpenVPNIsRunning()
	if !restarted {
		logging.Error("panel-triggered OpenVPN restart failed")
		writeEnvelope(w, false, "OpenVPN restart failed",
			map[string]any{"openvpn_running": running})
		return
	}
	writeOK(w, "OpenVPN restart command completed",
		map[string]any{"openvpn_running": running})
}

// handleRenewCert renews the OpenVPN server certificate and restarts
// OpenVPN, so the clients reconnect against the new one.
func (s *Server) handleRenewCert(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, true) {
		return
	}
	if err := pki.RenewServerCert(); err != nil {
		logging.Error("server certificate renewal failed: %v", err)
		writeFail(w, "Server certificate renewal failed — check the node logs")
		return
	}
	if !ovpn.RestartOpenVPN() {
		writeFail(w, "Certificate renewed, but OpenVPN did not restart — restart it manually")
		return
	}
	writeOK(w, "Server certificate renewed; OpenVPN restarted",
		map[string]any{"server_expiry": pki.CertExpiry(pki.ServerCert())})
}

// handleUpdate triggers the node's self-update.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, true) {
		return
	}
	appDir := envOr("APP_DIR", "")
	if appDir == "" {
		for _, c := range []string{"/opt/ovnode", "/usr/local/ovnode"} {
			if _, err := os.Stat(c + "/install.sh"); err == nil {
				appDir = c
				break
			}
		}
	}
	if appDir == "" {
		appDir = "/opt/ovnode"
	}
	if err := updater.TriggerUpdate(appDir); err != nil {
		writeFail(w, err.Error())
		return
	}
	writeOK(w, "Update started", nil)
}
