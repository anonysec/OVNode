// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"encoding/json"
	"testing"
)

// The vendored contract must parse and carry one row per route the panel
// calls. A truncated or hand-edited copy fails here rather than in CI.
func TestVendoredContractIsValid(t *testing.T) {
	var rows []struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	}
	if err := json.Unmarshal(ContractJSON, &rows); err != nil {
		t.Fatalf("contract.json does not parse: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("contract.json has no rows")
	}
	for _, r := range rows {
		if r.Method == "" || r.Path == "" {
			t.Errorf("row with empty method or path: %+v", r)
		}
	}
}
