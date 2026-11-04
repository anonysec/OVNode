package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleLogsClampAndValidate(t *testing.T) {
	s := testServer(t)
	// invalid level
	rec := do(t, s, http.MethodGet, "/sync/logs?level=FOO&limit=5", "")
	if rec.Code != http.StatusOK {
		// authorize passes; handler writes fail envelope with 200? check body success
	}
	body := envelopeOf(t, rec)
	if body["success"] != false {
		t.Fatalf("expected failure for invalid level, got %v", body["success"])
	}
	// negative limit
	rec = do(t, s, http.MethodGet, "/sync/logs?level=INFO&limit=-3", "")
	body = envelopeOf(t, rec)
	if body["success"] != false {
		t.Fatalf("expected failure for negative limit")
	}
	// valid
	rec = do(t, s, http.MethodGet, "/sync/logs?level=INFO&limit=10", "")
	body = envelopeOf(t, rec)
	if body["success"] != true {
		t.Fatalf("expected success, got %v", body["msg"])
	}
}

func TestGzipMiddlewareSkipsOVPNDownload(t *testing.T) {
	h := gzipMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 1024)))
	}))
	req := httptest.NewRequest(http.MethodGet, "/sync/download/ovpn/uid", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatal("expected no gzip for ovpn download")
	}
}

func TestAPIKeyTooShortRefused(t *testing.T) {
	s := testServer(t)
	s.APIKey = "short"
	rec := do(t, s, http.MethodGet, "/sync/status", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	// health still works
	rec = do(t, s, http.MethodGet, "/sync/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("health should work, got %d", rec.Code)
	}
}

func TestHandleDownloadOVPNAutoCreateHeavy(t *testing.T) {
	s := testServer(t)
	// ensure no profile; auto-create path should succeed with heavy auth
	rec := do(t, s, http.MethodGet, "/sync/download/ovpn/testuser", "")
	// may fail due to missing ovpn binary/env, but should not be 401/429
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusTooManyRequests {
		t.Fatalf("unexpected auth/ratelimit failure: %d", rec.Code)
	}
}

func TestHandleUpdateInvalidVersion(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, http.MethodPost, "/sync/update", `{"version":"1.2"}`)
	body := envelopeOf(t, rec)
	if body["success"] != false {
		t.Fatalf("expected failure, got %v", body["success"])
	}
	if msg, _ := body["msg"].(string); msg != "Invalid target version" {
		t.Fatalf("msg = %q, want %q", msg, "Invalid target version")
	}
}
