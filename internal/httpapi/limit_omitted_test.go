// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"testing"
)

// TestUserLimitOmittedIsRejected: an omitted max_logins must not mean
// unlimited on either the single or bulk endpoint.
func TestUserLimitOmittedIsRejected(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, http.MethodPut, "/sync/user/limit", `{"id":"alice"}`)
	if envelopeOf(t, rec)["success"] == true {
		t.Fatalf("PUT /sync/user/limit with omitted max_logins succeeded, want failure")
	}
}

func TestBulkLimitsOmittedIsFailed(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, http.MethodPost, "/sync/users", `{"users":[{"id":"alice"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /sync/users status = %d", rec.Code)
	}
	body := envelopeOf(t, rec)
	items, _ := body["data"].(map[string]any)["failed"].([]any)
	if len(items) == 0 {
		t.Fatalf("bulk item with omitted max_logins not failed: %v", body)
	}
}
