// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"ovnode/internal/pki"
	"ovnode/internal/store"
)

func TestApplyUserPolicyMergesAtomically(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	t.Setenv("OVNODE_DATA_DIR", root+"/ovnode-data")
	for _, d := range []string{
		filepath.Join(root, "server", "pki", "private"),
		filepath.Join(root, "server", "pki", "issued"),
		filepath.Join(root, "ovnode-data", "users"),
		filepath.Join(root, "ovnode-data", "sessions"),
		filepath.Join(root, "ovnode-data", "usage"),
	} {
		os.MkdirAll(d, 0o755)
	}
	cn := "mergeuser"
	if err := store.CreateUser(pki.UsersDir(), cn); err != nil {
		t.Fatal(err)
	}
	if err := store.SetDisabled(pki.UsersDir(), cn, true); err != nil {
		t.Fatal(err)
	}
	if err := store.SetLimit(pki.UsersDir(), cn, 2); err != nil {
		t.Fatal(err)
	}
	// Limit-only request must not clear disabled state.
	if err := SetUserLimit(cn, 7); err != nil {
		t.Fatal(err)
	}
	st, err := store.ReadUserState(pki.UsersDir(), cn)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Disabled {
		t.Fatal("disabled cleared by limit-only request")
	}
	if !st.LimitSet || st.Limit != 7 {
		t.Fatalf("limit not updated: %+v", st)
	}
	// Combined policy applies both.
	if err := ApplyUserPolicy(cn, "Alice", 3, false); err != nil {
		t.Fatal(err)
	}
	st, err = store.ReadUserState(pki.UsersDir(), cn)
	if err != nil {
		t.Fatal(err)
	}
	if st.Disabled {
		t.Fatal("disabled not cleared by combined activate")
	}
	if st.Limit != 3 {
		t.Fatalf("limit = %d, want 3", st.Limit)
	}
	if store.ReadName(pki.UsersDir(), cn) != "Alice" {
		t.Fatal("name not applied")
	}
}

func TestSetUserLimitNegativePreservesPolicy(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "app")
	if err := os.Mkdir(app, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, ".env"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OVN_APP_DIR", app)
	t.Setenv("OVNODE_OPENVPN_ROOT", filepath.Join(root, "vpn"))
	t.Setenv("OVNODE_DATA_DIR", filepath.Join(root, "data"))
	limit, disabled := 7, true
	if err := store.WriteUserState(pki.UsersDir(), "alice", &limit, &disabled); err != nil {
		t.Fatal(err)
	}
	for _, value := range []int{-1, -5} {
		if err := SetUserLimit("alice", value); err != nil {
			t.Fatal(err)
		}
		st, err := store.ReadUserState(pki.UsersDir(), "alice")
		if err != nil || st.Limit != 7 || !st.Disabled {
			t.Fatalf("negative limit %d changed existing policy: %+v (%v)", value, st, err)
		}
	}
	if err := SetUserLimit("alice", 0); err != nil {
		t.Fatal(err)
	}
	if st, err := store.ReadUserState(pki.UsersDir(), "alice"); err != nil || st.Limit != 0 || !st.Disabled {
		t.Fatalf("explicit unlimited must remain distinct: %+v (%v)", st, err)
	}
}

func TestApplyUserPolicyFailureDoesNotPartiallyChangeName(t *testing.T) {
	providerTree(t)
	if err := store.CreateUser(pki.UsersDir(), "alice"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(pki.UsersDir(), "alice")
	if err := os.WriteFile(filepath.Join(dir, "name"), []byte("Alice\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ApplyUserPolicy("alice", "Bob", 3, true); err == nil {
		t.Fatal("blocked state update reported success")
	}
	name, err := os.ReadFile(filepath.Join(dir, "name"))
	if err != nil || string(name) != "Alice\n" {
		t.Fatalf("failed complete policy changed the legacy name: %q (%v)", name, err)
	}
}

func TestPolicyUpdateMergesAtomically(t *testing.T) {
	providerTree(t)
	for range 12 {
		if err := ApplyUserPolicy("alice", "Alice", 1, false); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, update := range []func() error{func() error { return SetUserLimit("alice", 9) }, func() error { return SetUserStatus("alice", "deactivate") }} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := update(); err != nil {
					t.Error(err)
				}
			}()
		}
		close(start)
		wg.Wait()
		state, err := store.ReadUserState(pki.UsersDir(), "alice")
		if err != nil || !state.Disabled || state.Limit != 9 || store.ReadName(pki.UsersDir(), "alice") != "Alice" {
			t.Fatalf("concurrent partial updates lost desired policy: %+v (%v)", state, err)
		}
	}
}

func TestCompletePolicyIsOneSnapshot(t *testing.T) {
	providerTree(t)
	if err := ApplyUserPolicy("alice", "Alice", 0, false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(pki.UsersDir(), "alice", "state")
	valid := func() {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		fields := map[string]string{}
		for _, line := range strings.Split(string(data), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok {
				fields[key] = value
			}
		}
		alice := fields["name"] == "Alice" && fields["limit"] == "0" && fields["disabled"] == "0"
		bob := fields["name"] == "Bob" && fields["limit"] == "3" && fields["disabled"] == "1"
		if !alice && !bob {
			t.Errorf("complete desired policy is not one atomic snapshot: %q", data)
		}
	}
	valid()
	var wg sync.WaitGroup
	for _, name := range []string{"Alice", "Bob"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				limit, disabled := 0, false
				if name == "Bob" {
					limit, disabled = 3, true
				}
				if err := ApplyUserPolicy("alice", name, limit, disabled); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	for range 40 {
		valid()
	}
	wg.Wait()
	valid()
}
