// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"

	"ovnode/internal/pairing"
)

// The panel is the client: it sends the node API key in the "key" header
// and its identity in "X-Panel-ID".
//
// The API key says "you are allowed"; the pairing says "you are the owner".
// One panel owns a node at a time, so a second panel with a valid key is
// refused while the first one still holds the lease.

// authorize checks the API key, charges the rate limit and enforces the
// single-panel lease.
//
// The order matters: a missing key is a 401 (the diagnostic), not a 429
// that hides it. The rate limit is keyed on the connecting address, never on
// the submitted secret — keying on an attacker-supplied value gave every
// guess a fresh bucket, so brute force was unlimited and a flood of bogus
// keys evicted the real caller.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, heavy bool) bool {
	given := r.Header.Get("key")
	if given == "" {
		writeAuthError(w, http.StatusUnauthorized, "Missing API key")
		return false
	}
	client := clientAddr(r)
	if ok, retry := s.limiter.Allow(client); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
		writeAuthError(w, http.StatusTooManyRequests, "Rate limit exceeded")
		return false
	}
	if subtle.ConstantTimeCompare([]byte(given), []byte(s.APIKey)) != 1 {
		writeAuthError(w, http.StatusUnauthorized, "Invalid API key")
		return false
	}
	if heavy {
		if ok, retry := s.limiter.AllowHeavy(client); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
			writeAuthError(w, http.StatusTooManyRequests,
				"Too many certificate operations — slow down")
			return false
		}
	}
	// The pairing runs only after the key is proven: the panel id is
	// identity, not authentication.
	if err := pairing.Enforce(strings.TrimSpace(r.Header.Get("X-Panel-ID"))); err != nil {
		writeAuthError(w, http.StatusConflict,
			"Node is paired with another panel. Wait for the 30-minute lease "+
				"or run `ovnode auth disconnect` on this node.")
		return false
	}
	return true
}

// clientAddr returns the connecting address, the rate-limit key.
//
// Never the submitted secret: keying on an attacker-supplied value gave
// every guess a fresh bucket and a flood of bogus keys evicted the real
// caller.
func clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// writeAuthError answers a refusal with the status the panel expects: 401
// for a missing or bad key, 409 for a pairing conflict, 429 for the rate
// limit.
//
// The 409 body carries the explanation in "detail" and in "msg": the panel
// reads whichever it finds.
func writeAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]any{"success": false, "msg": msg, "data": nil}
	if status == http.StatusConflict {
		body["detail"] = msg
	}
	_ = json.NewEncoder(w).Encode(body)
}
