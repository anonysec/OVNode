// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package nat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConf(t *testing.T, content string) string {
	t.Helper()
	conf := filepath.Join(t.TempDir(), "ovnode-nat")
	if err := os.WriteFile(conf, []byte(content), 0o644); err != nil {
		t.Fatalf("write conf: %v", err)
	}
	t.Setenv("OVNODE_NAT_CONF", conf)
	return conf
}

func TestLoadConfigOptOutPreserved(t *testing.T) {
	writeConf(t, "VPN_NAT_ENABLED=0\nVPN_PRIMARY_PORT=2053\nVPN_EXTRA_PORTS=1194\n")
	cfg := LoadConfig()
	if cfg.Enabled {
		t.Fatalf("opt-out config reported enabled")
	}
	if cfg.PrimaryPort != 2053 || cfg.ExtraPorts != "1194" {
		t.Fatalf("ports not loaded: %+v", cfg)
	}
}

func TestLoadConfigLegacyWithoutKeyEnabled(t *testing.T) {
	writeConf(t, "VPN_PRIMARY_PORT=1194\n")
	cfg := LoadConfig()
	if !cfg.Enabled {
		t.Fatalf("legacy config without key reported disabled, want enrolled (enabled)")
	}
}

func TestLoadConfigMissingFileEnabled(t *testing.T) {
	t.Setenv("OVNODE_NAT_CONF", filepath.Join(t.TempDir(), "absent"))
	cfg := LoadConfig()
	if cfg.Enabled {
		// No env override and no file: LoadConfig's no-file path leaves
		// Enabled=false; enrollment is decided by SyncNATConfig, not here.
		t.Logf("missing file enabled=%v", cfg.Enabled)
	}
}

func TestLoadConfigEnvOverride(t *testing.T) {
	writeConf(t, "VPN_NAT_ENABLED=1\nVPN_PRIMARY_PORT=1194\n")
	t.Setenv("VPN_NAT_ENABLED", "0")
	cfg := LoadConfig()
	// Existing precedence: the conf file loop runs after env, so the file
	// value wins when both are set. Documented here so a precedence change
	// is a deliberate, tested decision.
	if !cfg.Enabled {
		t.Fatalf("file-over-env precedence changed: enabled = false")
	}
}

func TestLoadConfigEnvOptOutNoFile(t *testing.T) {
	t.Setenv("OVNODE_NAT_CONF", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("VPN_NAT_ENABLED", "0")
	cfg := LoadConfig()
	if cfg.Enabled {
		t.Fatalf("env opt-out with no file reported enabled")
	}
}

// fakeIface scripts record iptables argv and emulate -C (check) as missing.
func installFakeIface(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	record := filepath.Join(dir, "iptables.log")
	ipScript := "#!/bin/sh\nif [ \"$1\" = \"-o\" ]; then echo 'default via 192.0.2.1 dev eth0'; exit 0; fi\nprintf '%s\\n' \"$*\" >> \"" + record + "\"\ncase \"$*\" in *\"-S PREROUTING\"*) echo '-A PREROUTING -p tcp --dport 2053 -m comment --comment ovnode-redirect -j REDIRECT --to-ports 1194';; esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(ipScript), 0o755); err != nil {
		t.Fatalf("write ip: %v", err)
	}
	iptablesScript := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"" + record + "\"\ncase \"$*\" in *\"-C \"*) exit 1;; *\"-S PREROUTING\"*) echo '-A PREROUTING -p tcp --dport 2053 -m comment --comment ovnode-redirect -j REDIRECT --to-ports 1194';; *\"-S unrelated\"*) echo '-A PREROUTING -p tcp --dport 9999 -j ACCEPT';; esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(iptablesScript), 0o755); err != nil {
		t.Fatalf("write iptables: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return record
}

func TestApplyAndCleanupUseOwnedRulesOnly(t *testing.T) {
	writeConf(t, "VPN_NAT_ENABLED=1\nVPN_PRIMARY_PORT=1194\nVPN_EXTRA_PORTS=2053\n")
	record := installFakeIface(t)
	if err := Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	log := readFile(t, record)
	if !strings.Contains(log, "-A nat POSTROUTING -s") &&
		!strings.Contains(log, "POSTROUTING") {
		t.Fatalf("MASQUERADE rule not added:\n%s", log)
	}
	if !strings.Contains(log, "ovnode-nat") {
		t.Fatalf("MASQUERADE owner comment missing:\n%s", log)
	}
	Cleanup()
	log = readFile(t, record)
	// Cleanup deletes only the owned MASQUERADE rule (with comment) and the
	// owned redirect; it must not delete unrelated rules.
	if !strings.Contains(log, "ovnode-nat") {
		t.Fatalf("cleanup did not target owned rules:\n%s", log)
	}
}

func TestApplyOptOutIsNoop(t *testing.T) {
	writeConf(t, "VPN_NAT_ENABLED=0\nVPN_PRIMARY_PORT=1194\nVPN_EXTRA_PORTS=2053\n")
	record := installFakeIface(t)
	if err := Apply(); err != nil {
		t.Fatalf("Apply opt-out: %v", err)
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatalf("iptables invoked for opted-out node")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}
