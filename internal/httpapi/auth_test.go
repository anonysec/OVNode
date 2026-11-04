// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
