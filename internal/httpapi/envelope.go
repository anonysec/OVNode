// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"encoding/json"
	"net/http"
)

// envelope is the shape every /sync route answers.
//
// The panel reads success, msg and data; the data keys are the contract.
type envelope struct {
	Success bool   `json:"success"`
	Msg     string `json:"msg"`
	Data    any    `json:"data"`
}

// writeEnvelope answers with the standard envelope.
func writeEnvelope(w http.ResponseWriter, success bool, msg string, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(envelope{Success: success, Msg: msg, Data: data})
}

// writeOK answers a successful call.
func writeOK(w http.ResponseWriter, msg string, data any) {
	writeEnvelope(w, true, msg, data)
}

// writeFail answers a business failure.
//
// HTTP 200 with success false: the panel treats any other status as a
// transport error and retries loudly, which is not what a refused change
// is.
func writeFail(w http.ResponseWriter, msg string) {
	writeEnvelope(w, false, msg, nil)
}

// decodeBody reads a JSON body into v.
//
// A malformed body is a business failure, not a 500: the panel must see the
// refusal instead of a transport error it retries forever.
func decodeBody(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	return json.NewDecoder(r.Body).Decode(v)
}
