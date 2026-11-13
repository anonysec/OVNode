// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package commands

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A dead candidate must fail the probe; the old stub returned true and
// committed the update anyway.
func TestWaitHealthWaitsForARealAnswer(t *testing.T) {
	old := healthPoll
	healthPoll = time.Millisecond
	t.Cleanup(func() { healthPoll = old })

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if !waitHealth(srv.URL, 5) {
		t.Fatal("waitHealth = false, want true once the endpoint answers 200")
	}
	if calls != 3 {
		t.Fatalf("probes = %d, want 3", calls)
	}
}

func TestWaitHealthGivesUp(t *testing.T) {
	old := healthPoll
	healthPoll = time.Millisecond
	t.Cleanup(func() { healthPoll = old })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if waitHealth(srv.URL, 3) {
		t.Fatal("waitHealth = true, want false when the endpoint never answers 200")
	}
}
