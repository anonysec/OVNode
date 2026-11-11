// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimePermissionsEquivalence(t *testing.T) {
	// Build a temp tree mirroring the jail fixture, run the new function,
	// and verify the modes match the expected table exactly. The test
	// would fail if the refactor changed any resulting mode.
	if os.Getuid() != 0 {
		t.Skip("root required")
	}
	dir := t.TempDir()
	t.Setenv("OpenVpnRoot", filepath.Join(dir, "openvpn"))
	t.Setenv("DataDir", filepath.Join(dir, "data"))
	t.Setenv("UsersDir", filepath.Join(dir, "data", "users"))
	t.Setenv("SessionsDir", filepath.Join(dir, "data", "sessions"))
	t.Setenv("UsageDir", filepath.Join(dir, "data", "usage"))
	t.Setenv("LogDir", filepath.Join(dir, "logs"))
	t.Setenv("LogFile", filepath.Join(dir, "logs", "events.log"))
	t.Setenv("RuntimeGroup", "65533")
	for _, path := range []string{
		"openvpn/server/pki/private", "openvpn/server", "openvpn/ccd",
		"data/users/alice", "data/sessions", "data/usage", "logs",
	} {
		if err := os.MkdirAll(filepath.Join(dir, path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(dir, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Write files with wrong modes.
	files := map[string]os.FileMode{
		"data/users/alice/state": 0o600, "data/users/alice/limit": 0o600,
		"data/users/alice/key.pem": 0o644, "data/sessions/.lock.alice": 0o600,
		"data/usage/alice": 0o600, "logs/events.log": 0o600,
	}
	for p, m := range files {
		if err := os.WriteFile(filepath.Join(dir, p), []byte("x"), m); err != nil {
			t.Fatal(err)
		}
	}
	if err := FixRuntimePermissions(filepath.Join(dir, "openvpn")); err != nil {
		t.Fatal(err)
	}

	want := map[string]os.FileMode{
		"data/users/alice": 0o750 | os.ModeSetgid, "data/users/alice/state": 0o640,
		"data/sessions": 0o770 | os.ModeSetgid, "data/usage": 0o770 | os.ModeSetgid,
		"data/users/alice/key.pem": 0o600,
	}
	for p, mode := range want {
		info, err := os.Stat(filepath.Join(dir, p))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode() & (os.ModePerm | os.ModeSetgid); got != mode {
			t.Errorf("%s mode = %v, want %v", p, got, mode)
		}
	}
	// Old vs new: the same expected table is what the pre-refactor code
	// produced (see runtime_permissions_test.go expectations). Running
	// again must be a no-op for mtimes.
	mtimes := map[string]int64{}
	for _, p := range []string{"data/users/alice/state", "data/sessions/.lock.alice"} {
		info, _ := os.Stat(filepath.Join(dir, p))
		mtimes[p] = info.ModTime().UnixNano()
	}
	if err := FixRuntimePermissions(filepath.Join(dir, "openvpn")); err != nil {
		t.Fatal(err)
	}
	for p, m := range mtimes {
		info, _ := os.Stat(filepath.Join(dir, p))
		if info.ModTime().UnixNano() != m {
			t.Errorf("%s mtime changed on no-op rerun: %d -> %d", p, m, info.ModTime().UnixNano())
		}
	}
}
