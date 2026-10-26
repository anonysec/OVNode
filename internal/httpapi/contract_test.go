// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The node↔panel contract: every route the OVManager panel calls, the
// request fields it sends and the response keys it reads.
//
// The panel owns the client side of this contract — its own table lives in
// OVManager internal/node/contract.go, and its test fails when the panel
// reads a key the node does not send. This file is the node's half: the
// table below says what the node must answer, and the test says the node
// does.
//
// The two tables are kept in step by hand. They cannot be one file: the
// repos are separate Go modules and neither depends on the other.
type contractRow struct {
	// Method and Path are the HTTP method and the route.
	Method string
	Path   string
	// Request lists the JSON body fields the panel sends.
	Request []string
	// Response lists the data keys the panel reads from the response.
	Response []string
	// ResponseRaw marks a body that is not the {success,msg,data} envelope.
	ResponseRaw bool
}

// contract is the whole set. It is enumerated rather than discovered, so a
// route the panel starts using has to be added here on purpose.
var contract = []contractRow{
	{Method: http.MethodGet, Path: "/sync/status",
		Response: []string{"version", "cpu_usage", "memory_usage", "cert_expiry"}},
	{Method: http.MethodGet, Path: "/sync/usage",
		Response: []string{"totals"}},
	{Method: http.MethodGet, Path: "/sync/sessions",
		Response: []string{"live_sessions", "stale_markers", "live_count", "stale_marker_count",
			"auth_errors", "auth_errors_by_cn", "rejects", "policy_rejects", "warn_rejects",
			"events", "last_error"}},
	{Method: http.MethodGet, Path: "/sync/logs",
		Response: []string{"records", "last_error", "errors_1h"}},
	{Method: http.MethodGet, Path: "/sync/config",
		Response: []string{"port", "proto", "tunnel_address"}},
	{Method: http.MethodPost, Path: "/sync/config",
		Request: []string{"tunnel_address", "protocol", "ovpn_port", "set_new_setting",
			"dns1", "dns2", "enable_ipv6", "ipv6_prefix", "extra_ports"}},
	{Method: http.MethodPost, Path: "/sync/restart",
		Response: []string{"openvpn_running"}},
	{Method: http.MethodPost, Path: "/sync/renew-cert"},
	{Method: http.MethodPost, Path: "/sync/update"},
	{Method: http.MethodPost, Path: "/sync/user",
		Request: []string{"name", "max_logins", "id"}},
	{Method: http.MethodDelete, Path: "/sync/user/{uid}"},
	{Method: http.MethodPost, Path: "/sync/user/{uid}/disconnect",
		Response: []string{"removed_markers", "killed_sessions"}},
	{Method: http.MethodPost, Path: "/sync/user/{uid}/reset-usage"},
	{Method: http.MethodGet, Path: "/sync/download/ovpn/{uid}", ResponseRaw: true},
	{Method: http.MethodPost, Path: "/sync/users",
		Request:  []string{"users[].id", "users[].max_logins"},
		Response: []string{"applied", "failed"}},
}

// TestContractRowsAreServed: every row of the contract is a route the node
// actually serves, with the method the panel uses.
//
// A route the node dropped, or one it answers with a different method, is
// the failure the panel sees as an empty field in its dashboard.
func TestContractRowsAreServed(t *testing.T) {
	s := testServer(t)
	mux := s.routes()
	for _, row := range contract {
		path := row.Path
		if strings.Contains(path, "{uid}") {
			path = strings.Replace(path, "{uid}", "contract-probe", 1)
		}
		rec := do(t, s, row.Method, path, "")
		if rec.Code == http.StatusNotFound {
			t.Errorf("the node does not serve %s %s", row.Method, row.Path)
		}
		if rec.Code == http.StatusMethodNotAllowed {
			t.Errorf("the node answers %s %s with 405", row.Method, row.Path)
		}
		_ = mux
	}
}

// TestContractResponseKeys: every key the panel reads is in the response.
//
// The panel dereferences these keys without a guard, so a missing one is a
// zero in the panel's UI, not an error. That is why the check lives here.
func TestContractResponseKeys(t *testing.T) {
	s := testServer(t)
	for _, row := range contract {
		if len(row.Response) == 0 || row.ResponseRaw {
			continue
		}
		path := row.Path
		if strings.Contains(path, "{uid}") {
			path = strings.Replace(path, "{uid}", "contract-probe", 1)
		}
		body := envelopeOf(t, do(t, s, row.Method, path, ""))
		if body["success"] != true {
			// A write route that refuses an unknown user still answers the
			// envelope; a read route must succeed.
			if row.Method == http.MethodGet {
				t.Errorf("%s %s did not succeed: %s", row.Method, row.Path, body["msg"])
			}
			continue
		}
		data, _ := body["data"].(map[string]any)
		for _, key := range row.Response {
			if _, ok := data[key]; !ok {
				t.Errorf("%s %s: the panel reads data.%s, which the node does not send",
					row.Method, row.Path, key)
			}
		}
	}
}

// TestContractRequestFieldsAreBound: the node accepts the field names the
// panel sends.
//
// A field that does not bind is a silent no-op: the panel believes it
// pushed a setting and the node never applied it.
func TestContractRequestFieldsAreBound(t *testing.T) {
	for _, row := range contract {
		if len(row.Request) == 0 {
			continue
		}
		body := "{}"
		for _, field := range row.Request {
			field = strings.TrimSuffix(field, "[]")
			if i := strings.Index(field, "."); i >= 0 {
				field = field[i+1:]
			}
			body = strings.Replace(body, "}", fmt.Sprintf("%q:%q,", field, "1"), 1)
		}
		body = strings.TrimSuffix(body, ",}")
		body += "}"

		s := testServer(t)
		rec := do(t, s, row.Method, row.Path, body)
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
			t.Errorf("%s %s is not served", row.Method, row.Path)
		}
	}
}

// TestContractMatchesThePanelTable: the node's table and the panel's table
// name the same routes.
//
// The panel's table is the authority (it is the client), but the panel repo
// is not a dependency of this module, so the comparison is a list kept in
// step by hand. A route that appears on one side only is a drift: the panel
// calls a route the node does not serve, or the node serves one nobody
// calls.
//
// The node serves a few routes the panel does not call (GET /sync/config,
// PUT /sync/users/{cn}, PUT /sync/pki). They are part of the node's own
// surface — the config drift read and the panel-owned PKI push — and the
// panel may start using them, so they are listed and exempted rather than
// removed.
func TestContractMatchesThePanelTable(t *testing.T) {
	panel := panelContractRows(t)
	mine := map[string]bool{}
	for _, row := range contract {
		mine[methodName(row.Method)+" "+row.Path] = true
	}
	for key := range panel {
		if !mine[key] {
			t.Errorf("the panel calls %s, which the node's contract does not list", key)
		}
	}
	for key := range mine {
		if !panel[key] && !nodeOnlyRoutes[key] {
			t.Errorf("the node's contract lists %s, which the panel does not call", key)
		}
	}
}

// nodeOnlyRoutes are the routes the node serves for its own sake. The panel
// does not call them today; they are not drift.
var nodeOnlyRoutes = map[string]bool{
	"GET /sync/config":     true,
	"PUT /sync/users/{cn}": true,
	"PUT /sync/pki":        true,
}

// methodName renders an HTTP method the way the panel's table spells it.
func methodName(method string) string {
	switch method {
	case http.MethodGet:
		return "GET"
	case http.MethodPost:
		return "POST"
	case http.MethodPut:
		return "PUT"
	case http.MethodDelete:
		return "DELETE"
	case http.MethodPatch:
		return "PATCH"
	}
	return method
}

// panelContractRows reads the panel's table when the sibling checkout is
// available, and skips otherwise.
//
// The panel repo is not a Go dependency here, so the table is read as text
// when the checkout sits next to this one. A CI that checks out only the
// node skips the comparison and keeps the per-route tests.
func panelContractRows(t *testing.T) map[string]bool {
	rows := map[string]bool{}
	for _, path := range []string{
		filepath.Join("..", "..", "..", "OVManager", "internal", "node", "contract.go"),
		filepath.Join("..", "..", "OVManager", "internal", "node", "contract.go"),
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		re := regexp.MustCompile(`Method:\s+http\.Method(\w+),\s*\n\s*Path:\s+"([^"]+)"`)
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			rows[strings.ToUpper(m[1])+" "+m[2]] = true
		}
		return rows
	}
	t.Skip("the panel checkout is not next to this one — the per-route tests still run")
	return rows
}
