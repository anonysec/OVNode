// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"ovnode/internal/fsx"
	"ovnode/internal/logging"
	"ovnode/internal/ovpn"
	"ovnode/internal/pki"
	"ovnode/internal/store"
)

// The user routes.
//
// The panel sends the numeric user id when it knows it and the display name
// otherwise; the name becomes the identity with the spaces replaced by
// underscores, the same normalisation the panel applies.

// createUserRequest is the body of POST /sync/user.
type createUserRequest struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	MaxLogins *int   `json:"max_logins"`
}

// userStatusRequest is the body of PUT /sync/user.
type userStatusRequest struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	MaxLogins *int   `json:"max_logins"`
}

// userLimitRequest is the body of PUT /sync/user/limit.
type userLimitRequest struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	MaxLogins int    `json:"max_logins"`
}

// bulkLimitItem is one entry of POST /sync/users.
type bulkLimitItem struct {
	ID        string `json:"id"`
	MaxLogins int    `json:"max_logins"`
}

// bulkLimitsRequest is the body of POST /sync/users.
type bulkLimitsRequest struct {
	Users []bulkLimitItem `json:"users"`
}

// pushCredentialRequest is the body of PUT /sync/users/{cn}.
type pushCredentialRequest struct {
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	CAPEM     string `json:"ca_pem"`
	MaxLogins *int   `json:"max_logins"`
	Disabled  *bool  `json:"disabled"`
}

// pushPKIRequest is the body of PUT /sync/pki.
type pushPKIRequest struct {
	CAPEM         string `json:"ca_pem"`
	ServerCertPEM string `json:"server_cert_pem"`
	ServerKeyPEM  string `json:"server_key_pem"`
}

// resolveCN turns a panel identity into the OpenVPN common name.
func resolveCN(id, name string) (string, error) {
	ident := strings.TrimSpace(id)
	if ident == "" {
		ident = strings.TrimSpace(name)
		ident = strings.ReplaceAll(ident, " ", "_")
	}
	if ident == "" {
		return "", errInvalidUserID
	}
	return store.SafeCN(ident)
}

// errInvalidUserID is the refusal for an identity the node cannot use.
var errInvalidUserID = errors.New("Invalid user id (must be UUID or simple id)")

// handleUserCreate provisions a user: certificate, profile, name and limit.
func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, true) {
		return
	}
	var body createUserRequest
	if err := decodeBody(r, &body); err != nil {
		writeFail(w, "Invalid user payload")
		return
	}
	cn, err := resolveCN(body.ID, body.Name)
	if err != nil {
		writeFail(w, err.Error())
		return
	}
	maxLogins := 1
	if body.MaxLogins != nil && *body.MaxLogins >= 0 {
		maxLogins = *body.MaxLogins
	}
	if err := ovpn.CreateUser(cn, body.Name, maxLogins, nil); err != nil {
		logging.Error("could not create user %q: %v", cn, err)
		writeFail(w, "Failed to create user")
		return
	}
	logging.Info("user %q created (max_logins=%d)", cn, maxLogins)
	writeOK(w, "User created successfully", map[string]any{"id": cn, "name": body.Name})
}

// handleUserStatus activates or deactivates a user.
func (s *Server) handleUserStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, false) {
		return
	}
	var body userStatusRequest
	if err := decodeBody(r, &body); err != nil {
		writeFail(w, "Invalid user payload")
		return
	}
	cn, err := resolveCN(body.ID, body.Name)
	if err != nil {
		writeFail(w, err.Error())
		return
	}
	if body.MaxLogins != nil && *body.MaxLogins >= 0 {
		if err := ovpn.SetUserLimit(cn, *body.MaxLogins); err != nil {
			writeFail(w, "Failed to update user login limit")
			return
		}
	}
	status := body.Status
	if status == "" {
		status = "activate"
	}
	if err := ovpn.SetUserStatus(cn, status); err != nil {
		logging.Error("could not change the status of %q: %v", cn, err)
		writeFail(w, "Failed to change user status")
		return
	}
	logging.Info("user %q status set to %s", cn, status)
	writeOK(w, "User status changed successfully",
		map[string]any{"id": cn, "name": body.Name})
}

// handleUserLimit sets the max simultaneous logins of a user.
func (s *Server) handleUserLimit(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, false) {
		return
	}
	var body userLimitRequest
	if err := decodeBody(r, &body); err != nil {
		writeFail(w, "Invalid user payload")
		return
	}
	ident := strings.TrimSpace(body.ID)
	if ident == "" {
		ident = strings.TrimSpace(body.Name)
	}
	if ident == "" {
		writeFail(w, errInvalidUserID.Error())
		return
	}
	if err := ovpn.SetUserLimit(ident, body.MaxLogins); err != nil {
		writeFail(w, "Failed to update user login limit")
		return
	}
	writeOK(w, "User login limit updated successfully", map[string]any{
		"id":         ident,
		"name":       body.Name,
		"max_logins": body.MaxLogins,
	})
}

// handleUserDelete revokes the certificate of a user and removes its tree.
func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, true) {
		return
	}
	cn, err := store.SafeCN(strings.TrimSpace(r.PathValue("uid")))
	if err != nil {
		writeFail(w, errInvalidUserID.Error())
		return
	}
	found, err := ovpn.DeleteUser(cn)
	if err != nil {
		logging.Error("could not delete user %q: %v", cn, err)
		writeFail(w, "Failed to delete user")
		return
	}
	if !found {
		// Success, not a failure: the certificate is already gone, and the
		// panel's fan-out needs every node to answer true.
		writeOK(w, "User not found on node (already deleted)", nil)
		return
	}
	logging.Info("user %q revoked and removed", cn)
	writeOK(w, "User deleted successfully", map[string]any{"id": cn})
}

// handleUserDisconnect drops the sessions of a user.
//
// only_stale is the safe mode: it never kills a live session, it only drops
// the markers whose session is gone.
func (s *Server) handleUserDisconnect(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, false) {
		return
	}
	cn, err := store.SafeCN(strings.TrimSpace(r.PathValue("uid")))
	if err != nil {
		writeFail(w, errInvalidUserID.Error())
		return
	}
	onlyStale := false
	switch strings.ToLower(r.URL.Query().Get("only_stale")) {
	case "1", "true", "yes":
		onlyStale = true
	}
	removed, killed, mgmt := ovpn.DisconnectUser(cn, onlyStale)
	logging.Info("user %q disconnected (only_stale=%t, killed=%d, markers=%d)",
		cn, onlyStale, killed, len(removed))
	writeOK(w, "Disconnect command processed", map[string]any{
		"common_name":     cn,
		"removed_markers": removed,
		"killed_sessions": killed,
		"management":      mgmt,
	})
}

// handleResetUsage zeroes the banked traffic counters of a user.
func (s *Server) handleResetUsage(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, false) {
		return
	}
	cn, err := store.SafeCN(strings.TrimSpace(r.PathValue("uid")))
	if err != nil {
		writeFail(w, errInvalidUserID.Error())
		return
	}
	if err := store.ResetUsage(pki.UsageDir(), cn); err != nil {
		writeFail(w, "Failed to reset usage counters")
		return
	}
	writeOK(w, "Usage counters reset", map[string]any{"id": cn})
}

// handleDownloadOVPN returns the .ovpn profile of a user.
//
// The body is raw, not an envelope: the panel validates it (it must start
// with "client" or carry a "<ca>" block), so the profile is built here on
// the first download.
func (s *Server) handleDownloadOVPN(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, false) {
		return
	}
	cn, err := store.SafeCN(strings.TrimSpace(r.PathValue("uid")))
	if err != nil {
		writeFail(w, errInvalidUserID.Error())
		return
	}
	path, err := ovpn.UserProfilePath(cn)
	if err != nil {
		writeFail(w, "OVPN file not found")
		return
	}
	if _, err := os.Stat(path); err != nil {
		// Lazy creation on first download: mint client credentials if not yet present
		if err := ovpn.CreateUser(cn, "", 1, nil); err != nil {
			logging.Warn("could not auto-create user and profile for %q: %v", cn, err)
			writeFail(w, "OVPN file not found")
			return
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		writeFail(w, "OVPN file not found")
		return
	}
	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+cn+".ovpn\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleBulkLimits applies the max-login limits of many users in one call.
//
// A per-item failure lands in "failed": one broken user must not fail the
// whole sweep.
func (s *Server) handleBulkLimits(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, false) {
		return
	}
	var body bulkLimitsRequest
	if err := decodeBody(r, &body); err != nil {
		writeFail(w, "Invalid user payload")
		return
	}
	applied := 0
	failed := []map[string]any{}
	for _, item := range body.Users {
		ident := strings.TrimSpace(item.ID)
		if ident == "" {
			failed = append(failed, map[string]any{
				"id":  item.ID,
				"msg": errInvalidUserID.Error(),
			})
			continue
		}
		if err := ovpn.SetUserLimit(ident, item.MaxLogins); err != nil {
			failed = append(failed, map[string]any{
				"id":  item.ID,
				"msg": "Failed to update user login limit",
			})
			continue
		}
		applied++
	}
	writeOK(w, "limits applied", map[string]any{
		"applied": applied,
		"failed":  failed,
	})
}

// handlePushCreds stores the credentials the panel signed for a user.
//
// The panel owns the PKI: it signs the user certificate and pushes it here.
// The node stores it passively and never invokes a local CA.
func (s *Server) handlePushCreds(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, false) {
		return
	}
	cn, err := store.SafeCN(strings.TrimSpace(r.PathValue("cn")))
	if err != nil {
		writeFail(w, errInvalidUserID.Error())
		return
	}
	var body pushCredentialRequest
	if err := decodeBody(r, &body); err != nil {
		writeFail(w, "Invalid credential payload")
		return
	}
	maxLogins := 1
	if body.MaxLogins != nil && *body.MaxLogins >= 0 {
		maxLogins = *body.MaxLogins
	}
	if err := ovpn.CreateUserWithCredentials(cn, body.CertPEM, body.KeyPEM,
		body.CAPEM, maxLogins, body.Disabled); err != nil {
		logging.Error("could not store the credentials of %q: %v", cn, err)
		writeFail(w, "Failed to store pushed credentials")
		return
	}
	writeOK(w, "User credentials stored", map[string]any{"id": cn})
}

// handlePushPKI bootstraps the node PKI from the panel's material.
//
// The panel CA, the server certificate and the server key are written to the
// paths server.conf reads, then OpenVPN is reloaded (never restarted) when
// it is running.
func (s *Server) handlePushPKI(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, true) {
		return
	}
	var body pushPKIRequest
	if err := decodeBody(r, &body); err != nil {
		writeFail(w, "Invalid PKI payload")
		return
	}
	for _, item := range []struct {
		label, pem string
		path       string
		perm       os.FileMode
	}{
		{"ca_pem", body.CAPEM, pki.CACert(), 0o644},
		{"server_cert_pem", body.ServerCertPEM, pki.ServerCert(), 0o644},
		{"server_key_pem", body.ServerKeyPEM, pki.ServerKey(), 0o600},
	} {
		if !strings.Contains(item.pem, "-----BEGIN") {
			writeFail(w, item.label+" is not a PEM block")
			return
		}
		if err := os.MkdirAll(filepath.Dir(item.path), 0o755); err != nil {
			writeFail(w, "Failed to store pushed PKI")
			return
		}
		// Atomic: the server reads these files on the next start, and a
		// half-written certificate would lock every client out.
		if err := fsx.WriteFileAtomic(item.path, []byte(item.pem), item.perm); err != nil {
			logging.Error("could not store the pushed %s: %v", item.label, err)
			writeFail(w, "Failed to store pushed PKI")
			return
		}
	}
	reloaded := false
	if ovpn.OpenVPNIsRunning() {
		reloaded = ovpn.ReloadOpenVPN()
	}
	writeOK(w, "PKI stored", map[string]any{"reloaded": reloaded})
}
