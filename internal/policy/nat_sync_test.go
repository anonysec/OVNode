// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupNATConf creates a temp owned NAT config and a fake agent binary that
// records its argv, returning the conf path, the record file, and the app dir.
func setupNATConf(t *testing.T, initial string) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "ovnode-nat")
	if initial != "" {
		if err := os.WriteFile(conf, []byte(initial), 0o644); err != nil {
			t.Fatalf("write conf: %v", err)
		}
	}
	appDir := filepath.Join(dir, "app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("mkdir app: %v", err)
	}
	record := filepath.Join(dir, "nat-apply.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + record + "\"\n"
	if err := os.WriteFile(filepath.Join(appDir, "ovnode-server"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake agent: %v", err)
	}
	t.Setenv("OVNODE_NAT_CONF", conf)
	t.Setenv("OVN_APP_DIR", appDir)
	return conf, record, appDir
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func TestSyncNATConfigNotEnrolled(t *testing.T) {
	conf, _, _ := setupNATConf(t, "")
	if err := SyncNATConfig(1194, []int{2053}); err != nil {
		t.Fatalf("not enrolled: %v", err)
	}
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Fatalf("config file created for unenrolled node: %v", err)
	}
}

func TestSyncNATConfigOptOutSkipsApply(t *testing.T) {
	conf, record, _ := setupNATConf(t, "# OVNode NAT configuration\nVPN_NAT_ENABLED=0\nVPN_PRIMARY_PORT=1194\nVPN_EXTRA_PORTS=\n")
	if err := SyncNATConfig(2053, []int{1194}); err != nil {
		t.Fatalf("opt-out sync: %v", err)
	}
	content := readFile(t, conf)
	if !strings.Contains(content, "VPN_NAT_ENABLED=0") {
		t.Fatalf("opt-out not retained:\n%s", content)
	}
	if !strings.Contains(content, "VPN_PRIMARY_PORT=2053") || !strings.Contains(content, "VPN_EXTRA_PORTS=1194") {
		t.Fatalf("ports not rewritten on opt-out:\n%s", content)
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatalf("nat apply invoked for opted-out node")
	}
}

func TestSyncNATConfigEnabledApplies(t *testing.T) {
	conf, record, _ := setupNATConf(t, "VPN_NAT_ENABLED=1\nVPN_PRIMARY_PORT=1194\nVPN_EXTRA_PORTS=\n")
	if err := SyncNATConfig(2053, []int{1194}); err != nil {
		t.Fatalf("enabled sync: %v", err)
	}
	content := readFile(t, conf)
	if !strings.Contains(content, "VPN_NAT_ENABLED=1") ||
		!strings.Contains(content, "VPN_PRIMARY_PORT=2053") ||
		!strings.Contains(content, "VPN_EXTRA_PORTS=1194") {
		t.Fatalf("config not rewritten:\n%s", content)
	}
	args := readFile(t, record)
	if args != "nat\napply\n" {
		t.Fatalf("fake agent argv = %q, want nat apply", args)
	}
}

func TestSyncNATConfigApplyFailureRestoresPrevious(t *testing.T) {
	initial := "VPN_NAT_ENABLED=1\nVPN_PRIMARY_PORT=1194\nVPN_EXTRA_PORTS=8443\n"
	conf, _, appDir := setupNATConf(t, initial)
	// Failing agent binary.
	if err := os.WriteFile(filepath.Join(appDir, "ovnode-server"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("write failing agent: %v", err)
	}
	if err := SyncNATConfig(2053, []int{1194}); err == nil {
		t.Fatalf("apply failure returned nil error")
	}
	if got := readFile(t, conf); got != initial {
		t.Fatalf("previous config not restored:\ngot %q\nwant %q", got, initial)
	}
}
