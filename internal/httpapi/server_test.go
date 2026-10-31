// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovnode/internal/ratelimit"
)

const testKey = "test-key"

// testServer builds a server on a throwaway OpenVPN root.
func testServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	for _, d := range []string{
		filepath.Join(dir, "server", "pki", "private"),
		filepath.Join(dir, "server", "pki", "issued"),
		filepath.Join(dir, "ovnode", "users"),
		filepath.Join(dir, "ovnode", "sessions"),
		filepath.Join(dir, "ovnode", "usage"),
		filepath.Join(dir, "ovnode", "state"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &Server{APIKey: testKey, limiter: ratelimit.New(), started: time.Now()}
}

// do issues a request against the route table.
func do(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("key", testKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	return rec
}

// envelopeOf decodes the standard envelope of a response.
func envelopeOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not an envelope: %v (%s)", err, rec.Body.String())
	}
	return body
}

// TestRouteTableRegistersWithoutConflicts covers the method-scoped patterns.
//
// Go's ServeMux panics when two patterns overlap, so registering the table
// is the check: a method-blind table and a scoped one cannot live together.
func TestRouteTableRegistersWithoutConflicts(t *testing.T) {
	s := testServer(t)
	if mux := s.routes(); mux == nil {
		t.Fatal("no route table")
	}
}

// TestRoutesAreMethodScoped covers the method-blind table.
//
// One path serving three methods is how a PUT /sync/user/limit ended up
// deleting a user named "limit": the panel's limit push removed a real
// user.
func TestRoutesAreMethodScoped(t *testing.T) {
	s := testServer(t)
	root := os.Getenv("OVNODE_OPENVPN_ROOT")
	userDir := filepath.Join(root, "ovnode", "users", "limit")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDir, "name"), []byte("limit\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := do(t, s, http.MethodPut, "/sync/user/limit", `{"id":"limit","max_logins":2}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /sync/user/limit status = %d, want 200", rec.Code)
	}
	if _, err := os.Stat(userDir); err != nil {
		t.Fatalf("the user \"limit\" was removed by the limit route: %v", err)
	}

	// The bulk route must not answer the single-user create route: it
	// applies a limit, it does not provision a certificate.
	rec = do(t, s, http.MethodPost, "/sync/users", `{"users":[{"id":"bulk","max_logins":1}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /sync/users status = %d, want 200", rec.Code)
	}
	body := envelopeOf(t, rec)
	if body["success"] != true {
		t.Fatalf("POST /sync/users success = %v, want true (%s)", body["success"], rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "server", "pki", "issued", "bulk.crt")); err == nil {
		t.Fatal("the bulk route issued a certificate")
	}
}

// TestRouteTableRejectsAMethodMismatch covers the 405 the method-scoped
// table gives: the node must not answer a route it does not have.
func TestRouteTableRejectsAMethodMismatch(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, http.MethodDelete, "/sync/users/bulk", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE /sync/users/bulk status = %d, want 405", rec.Code)
	}
}

// TestMissingKeyIsUnauthorized covers the 401 of a request without a key.
func TestMissingKeyIsUnauthorized(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/sync/status", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestBadKeyIsUnauthorized covers the 401 of a wrong key.
func TestBadKeyIsUnauthorized(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/sync/status", nil)
	req.Header.Set("key", "wrong")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestPairingConflictIsA409 covers the single-panel lease.
//
// The body must carry the explanation in "detail" or in "msg": the panel
// reads whichever it finds and shows it to the operator.
func TestPairingConflictIsA409(t *testing.T) {
	s := testServer(t)
	// The first panel takes the lease.
	req := httptest.NewRequest(http.MethodGet, "/sync/status", nil)
	req.Header.Set("key", testKey)
	req.Header.Set("X-Panel-ID", "panel-a")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the first panel was refused: %d", rec.Code)
	}
	// A second panel is refused while the lease holds.
	req = httptest.NewRequest(http.MethodGet, "/sync/status", nil)
	req.Header.Set("key", testKey)
	req.Header.Set("X-Panel-ID", "panel-b")
	rec = httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	body := envelopeOf(t, rec)
	detail, _ := body["detail"].(string)
	msg, _ := body["msg"].(string)
	if strings.TrimSpace(detail) == "" && strings.TrimSpace(msg) == "" {
		t.Fatalf("the 409 body carries no explanation: %s", rec.Body.String())
	}
}

// TestRateLimitIsA429WithRetryAfter covers the rate limit refusal.
func TestRateLimitIsA429WithRetryAfter(t *testing.T) {
	s := testServer(t)
	var last *httptest.ResponseRecorder
	for i := 0; i < 200; i++ {
		last = do(t, s, http.MethodGet, "/sync/status", "")
		if last.Code == http.StatusTooManyRequests {
			break
		}
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 after 200 requests", last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Fatal("the 429 carries no Retry-After header")
	}
}

// TestStatusCarriesThePanelKeys covers the keys the panel dereferences on
// GET /sync/status.
func TestStatusCarriesThePanelKeys(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, http.MethodGet, "/sync/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := envelopeOf(t, rec)
	data, _ := body["data"].(map[string]any)
	if data == nil {
		t.Fatalf("no data object: %s", rec.Body.String())
	}
	for _, key := range []string{"version", "cpu_usage", "memory_usage", "cert_expiry"} {
		if _, ok := data[key]; !ok {
			t.Errorf("the status has no %q key: %s", key, rec.Body.String())
		}
	}
	if data["version"] != "1.4.3" {
		t.Errorf("version = %v, want the agent version", data["version"])
	}
}

// TestConfigPostHonoursSetNewSetting covers the no-op push.
//
// The panel sends set_new_setting=false when it only reads the settings; the
// node must answer success without touching the configuration.
func TestConfigPostHonoursSetNewSetting(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, http.MethodPost, "/sync/config",
		`{"tunnel_address":"1.2.3.4","protocol":"tcp","ovpn_port":1194,"set_new_setting":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := envelopeOf(t, rec)
	if body["success"] != true {
		t.Fatalf("success = %v, want true", body["success"])
	}
	if msg, _ := body["msg"].(string); msg != "No changes requested" {
		t.Fatalf("msg = %q, want %q", msg, "No changes requested")
	}
}

// TestConfigPostBindsThePanelFieldNames covers the json tags of the
// configuration request.
//
// Without them Go's case-insensitive matching leaves "ovpn_port" unbound
// and the panel's push is a no-op that reports success.
func TestConfigPostBindsThePanelFieldNames(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, http.MethodPost, "/sync/config",
		`{"tunnel_address":"1.2.3.4","protocol":"tcp","ovpn_port":1194,"set_new_setting":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := envelopeOf(t, rec)
	// The change fails on a tree without a server.conf, but the request
	// must have been understood: the port reached the change.
	if msg, _ := body["msg"].(string); msg == "Invalid configuration payload" {
		t.Fatalf("the configuration body was not decoded: %s", rec.Body.String())
	}
}

// TestDownloadOVPNRejectsAnUnknownUser covers the envelope failure of a
// profile that does not exist.
//
// The body is raw, not an envelope, so the failure has to be the envelope
// the panel can read.
func TestDownloadOVPNRejectsAnUnknownUser(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, http.MethodGet, "/sync/download/ovpn/nobody", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := envelopeOf(t, rec)
	if body["success"] != false {
		t.Fatalf("success = %v, want false", body["success"])
	}
}

// TestUserRoutesAnswerInsideTheEnvelope covers the panel's write routes on
// a user that does not exist: the node must answer, not fail with a 500.
func TestUserRoutesAnswerInsideTheEnvelope(t *testing.T) {
	s := testServer(t)
	cases := []struct {
		method, path, body string
	}{
		{http.MethodPut, "/sync/user", `{"id":"nobody","status":"activate"}`},
		{http.MethodPut, "/sync/user/limit", `{"id":"nobody","max_logins":1}`},
		{http.MethodPost, "/sync/users", `{"users":[{"id":"nobody","max_logins":1}]}`},
		{http.MethodPost, "/sync/user/nobody/disconnect", ""},
		{http.MethodPost, "/sync/user/nobody/reset-usage", ""},
		{http.MethodDelete, "/sync/user/nobody", ""},
	}
	for _, c := range cases {
		rec := do(t, s, c.method, c.path, c.body)
		if rec.Code != http.StatusOK {
			t.Errorf("%s %s status = %d, want 200", c.method, c.path, rec.Code)
			continue
		}
		body := envelopeOf(t, rec)
		if _, ok := body["success"]; !ok {
			t.Errorf("%s %s has no success key: %s", c.method, c.path, rec.Body.String())
		}
	}
}

// TestBulkLimitsReportPerItemFailures covers the bulk sweep: one broken
// user must not fail the whole call.
func TestBulkLimitsReportPerItemFailures(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, http.MethodPost, "/sync/users",
		`{"users":[{"id":"ok-one","max_logins":2},{"id":"","max_logins":1}]}`)
	body := envelopeOf(t, rec)
	data, _ := body["data"].(map[string]any)
	if data == nil {
		t.Fatalf("no data object: %s", rec.Body.String())
	}
	applied, _ := data["applied"].(float64)
	if int(applied) != 1 {
		t.Errorf("applied = %v, want 1", data["applied"])
	}
	failed, _ := data["failed"].([]any)
	if len(failed) != 1 {
		t.Errorf("failed = %v, want one entry", data["failed"])
	}
}

func TestDecodeBodyEnforcesMaxBytes(t *testing.T) {
	s := testServer(t)
	huge := strings.Repeat("a", (1<<20)+1024)
	hugeJSON := `{"id":"test","token":"` + huge + `"}`
	rec := do(t, s, http.MethodPost, "/sync/user", hugeJSON)
	body := envelopeOf(t, rec)
	if body["success"] == true {
		t.Fatal("oversized body should fail decode")
	}
}
