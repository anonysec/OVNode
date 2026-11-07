// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"ovnode/internal/pki"
	"ovnode/internal/store"
)

func TestNegativeLimitRoutesPreservePolicy(t *testing.T) {
	app := t.TempDir()
	if err := os.WriteFile(filepath.Join(app, ".env"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OVN_APP_DIR", app)
	for _, method := range []string{http.MethodPut, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			s := testServer(t)
			limit, disabled := 7, true
			if err := store.WriteUserState(pki.UsersDir(), "alice", &limit, &disabled); err != nil {
				t.Fatal(err)
			}
			path, body := "/sync/user/limit", `{"id":"alice","max_logins":-1}`
			if method == http.MethodPost {
				path, body = "/sync/users", `{"users":[{"id":"alice","max_logins":-1}]}`
			}
			response := envelopeOf(t, do(t, s, method, path, body))
			if response["success"] != true {
				t.Fatalf("negative-limit no-op request failed: %v", response)
			}
			st, err := store.ReadUserState(pki.UsersDir(), "alice")
			if err != nil || st.Limit != 7 || !st.Disabled {
				t.Fatalf("%s negative limit changed existing policy: %+v (%v)", method, st, err)
			}
		})
	}
}
