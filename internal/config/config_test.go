// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ovnode/internal/fsx"
)

func TestHookFromEnvUsesEffectiveFSXPaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OpenVpnRoot", filepath.Join(dir, "vpn"))
	t.Setenv("DataDir", filepath.Join(dir, "relocated-data"))
	for _, name := range []string{"UsersDir", "SessionsDir", "UsageDir"} {
		t.Setenv(name, "")
	}
	t.Setenv("LogDir", filepath.Join(dir, "logs"))
	t.Setenv("StatusFile", filepath.Join(dir, "status"))
	t.Setenv("MgmtPassFile", filepath.Join(dir, "password"))
	cfg := HookFromEnv()
	for _, pair := range [][2]string{{cfg.UsersDir, fsx.UsersDir()}, {cfg.SessionsDir, fsx.SessionsDir()}, {cfg.UsageDir, fsx.UsageDir()}, {cfg.MgmtPassFile, fsx.MgmtPassFile()}} {
		if pair[0] != pair[1] {
			t.Errorf("hook path %q disagrees with fsx path %q", pair[0], pair[1])
		}
	}
}

func TestHookFromEnvValidatesRanges(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OpenVpnRoot", dir)
	t.Setenv("DataDir", dir+"/ovnode-data")
	t.Setenv("ManagementPort", "0")
	t.Setenv("SessionTtlSeconds", "-5")
	// Keep the hook event log inside the sandbox: HookFromEnv writes the
	// fallback lines to LogDir/hook-events.log, so pointing LogDir at
	// the temp dir makes this test self-contained (no dependency on
	// /var/log/ovnode or root).
	t.Setenv("LogDir", dir)
	cfg := HookFromEnv()
	if cfg.MgmtPort != DefaultMgmtPort {
		t.Fatalf("mgmt port = %d, want %d", cfg.MgmtPort, DefaultMgmtPort)
	}
	if cfg.SessionTTL != DefaultSessionTTL {
		t.Fatalf("session ttl = %d, want %d", cfg.SessionTTL, DefaultSessionTTL)
	}
	// event log should mention fallback
	data, _ := os.ReadFile(filepath.Join(cfg.LogDir, "hook-events.log"))
	if !strings.Contains(string(data), "invalid") {
		t.Fatalf("expected fallback log, got %q", string(data))
	}
}
