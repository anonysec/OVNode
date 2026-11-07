// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"testing"

	"ovnode/internal/fsx"
)

func TestHookFromEnvUsesEffectiveFSXPaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", filepath.Join(dir, "vpn"))
	t.Setenv("OVNODE_DATA_DIR", filepath.Join(dir, "relocated-data"))
	for _, name := range []string{"OVNODE_USERS_DIR", "OVNODE_SESSIONS_DIR", "OVNODE_USAGE_DIR"} {
		t.Setenv(name, "")
	}
	t.Setenv("OVNODE_LOG_DIR", filepath.Join(dir, "logs"))
	t.Setenv("OVNODE_STATUS_FILE", filepath.Join(dir, "status"))
	t.Setenv("OVNODE_MGMT_PASS_FILE", filepath.Join(dir, "password"))
	cfg := HookFromEnv()
	for _, pair := range [][2]string{{cfg.UsersDir, fsx.UsersDir()}, {cfg.SessionsDir, fsx.SessionsDir()}, {cfg.UsageDir, fsx.UsageDir()}, {cfg.MgmtPassFile, fsx.MgmtPassFile()}} {
		if pair[0] != pair[1] {
			t.Errorf("hook path %q disagrees with fsx path %q", pair[0], pair[1])
		}
	}
}

func TestHookFromEnvValidatesRanges(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	t.Setenv("OVNODE_DATA_DIR", dir+"/ovnode-data")
	t.Setenv("OVNODE_MANAGEMENT_PORT", "0")
	t.Setenv("OVNODE_SESSION_TTL", "-5")
	// Keep the hook event log inside the sandbox: HookFromEnv writes the
	// fallback lines to LogDir/hook-events.log, so pointing OVNODE_LOG_DIR at
	// the temp dir makes this test self-contained (no dependency on
	// /var/log/ovnode or root).
	t.Setenv("OVNODE_LOG_DIR", dir)
	cfg := HookFromEnv()
	if cfg.MgmtPort != DefaultMgmtPort {
		t.Fatalf("mgmt port = %d, want %d", cfg.MgmtPort, DefaultMgmtPort)
	}
	if cfg.SessionTTL != DefaultSessionTTL {
		t.Fatalf("session ttl = %d, want %d", cfg.SessionTTL, DefaultSessionTTL)
	}
	// event log should mention fallback
	data, _ := os.ReadFile(filepath.Join(cfg.LogDir, "hook-events.log"))
	if !contains(string(data), "invalid") {
		t.Fatalf("expected fallback log, got %q", string(data))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
