// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ovnode/internal/logging"
)

func TestFailedAuthLockoutBlocksCorrectKey(t *testing.T) {
	s := testServer(t)
	ip := "203.0.113.9"
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/sync/status", nil)
		req.RemoteAddr = ip + ":1234"
		req.Header.Set("key", "wrong")
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong-key request %d status = %d, want 401", i+1, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/sync/status", nil)
	req.RemoteAddr = ip + ":1234"
	req.Header.Set("key", testKey)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked-out correct key status = %d, want 429", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/sync/status", nil)
	req2.RemoteAddr = "198.51.100.7:1234"
	req2.Header.Set("key", testKey)
	rec2 := httptest.NewRecorder()
	s.routes().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("different IP correct key status = %d, want 200", rec2.Code)
	}
}

func TestPanelAllowBlocksOtherIPs(t *testing.T) {
	s := testServer(t)
	s.panelAllow, s.allowEmpty = parsePanelAllow("203.0.113.0/24")
	if s.allowEmpty {
		t.Fatal("allowlist parsed as empty")
	}
	for _, tc := range []struct {
		remote string
		want   bool
	}{
		{"203.0.113.9:1234", true},
		{"198.51.100.7:1234", false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/sync/status", nil)
		req.RemoteAddr = tc.remote
		req.Header.Set("key", testKey)
		rec := httptest.NewRecorder()
		s.panelAllowMiddleware(s.routes()).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("remote %s status = %d, want 200 (envelope carries the verdict)", tc.remote, rec.Code)
		}
		if got := envelopeOf(t, rec)["success"] == true; got != tc.want {
			t.Fatalf("remote %s success = %v, want %v", tc.remote, got, tc.want)
		}
	}
}

func TestPanelAllowEmptyAllowsAnyIP(t *testing.T) {
	s := testServer(t)
	s.panelAllow, s.allowEmpty = parsePanelAllow("")
	if !s.allowEmpty {
		t.Fatal("empty spec must mean allow-all")
	}
	req := httptest.NewRequest(http.MethodGet, "/sync/status", nil)
	req.RemoteAddr = "198.51.100.7:1234"
	req.Header.Set("key", testKey)
	rec := httptest.NewRecorder()
	s.panelAllowMiddleware(s.routes()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestShortAPIKeyWarnsAtStart(t *testing.T) {
	before := len(logging.Recent("WARNING", logging.RingSize))
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	t.Setenv("API_KEY", "sixteen-char-key") // 16 chars: accepted, below 32
	if err := Run(); err == nil {
		t.Fatal("Run with missing TLS must fail before serving")
	}
	after := logging.Recent("WARNING", logging.RingSize)
	found := false
	for _, r := range after[before:] {
		if strings.Contains(r.Message, "shorter than 32") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no short-key warning in %v", after[before:])
	}
}

func TestAuthorizeChargesOncePerRequest(t *testing.T) {
	s := testServer(t)
	ip := "203.0.113.50:1234"
	for i := 0; i < 120; i++ {
		req := httptest.NewRequest(http.MethodGet, "/sync/status", nil)
		req.RemoteAddr = ip
		req.Header.Set("key", testKey)
		if !s.authorize(httptest.NewRecorder(), req, false) {
			t.Fatalf("call %d blocked early", i+1)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/sync/status", nil)
	req.RemoteAddr = ip
	req.Header.Set("key", testKey)
	rec := httptest.NewRecorder()
	if s.authorize(rec, req, false) {
		t.Fatal("121st call should be blocked (exactly 120 charges in 120 calls)")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("121st status = %d, want 429", rec.Code)
	}
}

func TestHeavyBucketExhaustionReturns429(t *testing.T) {
	s := testServer(t)
	ip := "203.0.113.60:1234"
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest(http.MethodPost, "/sync/user", nil)
		req.RemoteAddr = ip
		req.Header.Set("key", testKey)
		if !s.authorize(httptest.NewRecorder(), req, true) {
			t.Fatalf("heavy call %d blocked early", i+1)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/sync/user", nil)
	req.RemoteAddr = ip
	req.Header.Set("key", testKey)
	rec := httptest.NewRecorder()
	if s.authorize(rec, req, true) {
		t.Fatal("61st heavy call should be blocked")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("61st heavy status = %d, want 429", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "certificate") {
		t.Fatalf("429 body = %q, want certificate slowdown text", rec.Body.String())
	}
}
