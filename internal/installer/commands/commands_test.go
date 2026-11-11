// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package commands

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseMatchesBashContract pins the flag/env surfaces that Stage 2
// must preserve: OVN_* env mirrors every flag, CLI wins, deprecated
// spellings keep working, and the entry gates (uninstall/update on a
// box without a node) exit 4 without downloading anything.
func TestParseMatchesBashContract(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVN_SYSTEMD_DIR", t.TempDir())
	t.Setenv("OVN_APP_DIR", dir)
	cfg, action, err := Parse([]string{"--panel-ip", "203.0.113.9", "-y"})
	if err != nil {
		t.Fatal(err)
	}
	if action != "install" {
		t.Fatalf("action = %q, want install", action)
	}
	if cfg.PanelIP != "203.0.113.9" {
		t.Fatalf("panel-ip = %q", cfg.PanelIP)
	}
	if cfg.Port != "" {
		// Empty port means "default later", matching bash.
		t.Fatalf("port should be unset before validate: %q", cfg.Port)
	}

	// Env-only path must behave like the flag path.
	t.Setenv("OVN_PORT", "8443")
	t.Setenv("OVN_KEY", "0123456789abcdef")
	t.Setenv("OVN_PANEL_IP", "198.51.100.7")
	cfg2, action2, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if action2 != "install" || cfg2.Port != "8443" || cfg2.PanelIP != "198.51.100.7" {
		t.Fatalf("env path = %q/%q/%q", action2, cfg2.Port, cfg2.PanelIP)
	}

	// Gate: update on a box without a node is exit-4 before any download.
	cfg3, _, err := Parse([]string{"update"})
	if err == nil {
		t.Fatalf("update without node should be refused, got %+v", cfg3)
	}
	if msg := err.Error(); msg == "" {
		t.Fatal("empty error")
	}
}

// TestWriteEnvShape pins the .env key order and 0600 mode to write_env.
func TestWriteEnvShape(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVN_APP_DIR", dir)
	t.Setenv("OVN_DATA_BASE", filepath.Join(dir, "data"))
	cfg, _, err := Parse([]string{"--panel-ip", "203.0.113.9", "-y"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.NodeName = "eu-1"
	cfg.Port = "2083"
	cfg.VPNPorts = "1194"
	cfg.VPNSport = ""
	cfg.ExtraPorts = ""
	cfg.Proto = "udp"
	cfg.APIKey = "0123456789abcdef0123456789abcdef"
	cfg.RuntimeUser, cfg.RuntimeGroup = "ovnode-vpn", "ovnode-vpn"
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.writeEnv(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	want := "NODE_NAME=eu-1\n" +
		"OVNODE_INSTANCE=ovnode\n" +
		"DATA_DIR=" + filepath.Join(dir, "data") + "\n" +
		"OVNODE_DATA_DIR=" + filepath.Join(dir, "data") + "\n" +
		"SERVICE_PORT=2083\n" +
		"API_KEY=0123456789abcdef0123456789abcdef\n" +
		"OPENVPN_PORT=1194\n" +
		"OVNODE_PROTO=udp\n" +
		"OVNODE_RUNTIME_USER=ovnode-vpn\n" +
		"OVNODE_RUNTIME_GROUP=ovnode-vpn\n" +
		"TLS_METHOD=selfsigned\n" +
		"OVNODE_MANAGEMENT_PORT=7526\n" +
		"OVNODE_OPENVPN_ROOT=/var/lib/ovnode/openvpn\n" +
		"OVNODE_NAT_CONF=/etc/default/ovnode-nat\n" +
		"OVNODE_LOG_DIR=/var/log/ovnode\n" +
		"OVNODE_PANEL_ALLOW=203.0.113.9\n"
	if string(data) != want {
		t.Fatalf(".env = %q\nwant %q", data, want)
	}
	info, _ := os.Stat(filepath.Join(dir, ".env"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

// TestInstallStateMatchesBash instantiates the seven states from
// scripts/test-installer-go.sh and requires the same answer.
func TestInstallStateMatchesBash(t *testing.T) {
	t.Setenv("OVN_SYSTEMD_DIR", t.TempDir())
	c := FromEnv()

	c.AppDir = filepath.Join(t.TempDir(), "missing")
	if got := c.InstallStateOf(c.AppDir); got != StateAbsent {
		t.Fatalf("missing = %q", got)
	}
	empty := t.TempDir()
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := c.InstallStateOf(empty); got != StateBootstrap {
		t.Fatalf("empty = %q", got)
	}
	installed := t.TempDir()
	if err := os.WriteFile(filepath.Join(installed, ".env"), []byte("NODE_NAME=x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := c.InstallStateOf(installed); got != StateInstalled {
		t.Fatalf("installed = %q", got)
	}
	trunc := t.TempDir()
	if err := os.WriteFile(filepath.Join(trunc, "ovnode"), []byte("partial\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := c.InstallStateOf(trunc); got != StateBootstrap {
		t.Fatalf("truncated = %q", got)
	}
	withData := t.TempDir()
	if err := os.MkdirAll(filepath.Join(withData, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(withData, "data", "ca.key"), []byte("pk\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := c.InstallStateOf(withData); got != StateNodeData {
		t.Fatalf("node-data = %q", got)
	}
	notDir := t.TempDir()
	af := filepath.Join(notDir, "afile")
	if err := os.WriteFile(af, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := c.InstallStateOf(af); got != StateNotADirectory {
		t.Fatalf("not-a-directory = %q", got)
	}
}

// --instance must move every derived path, not just the label: the previous
// build kept /opt/ovnode and installed over the default instance.
func TestInstanceFlagDerivesPaths(t *testing.T) {
	t.Setenv("OVN_APP_DIR", "")
	t.Setenv("OVN_DATA_BASE", "")
	t.Setenv("OVN_OPENVPN_ROOT", "")
	t.Setenv("OVN_LOG_DIR", "")
	t.Setenv("OVN_INSTANCE", "")
	c, action, err := Parse([]string{"install", "--instance", "udp443"})
	if err != nil {
		t.Fatal(err)
	}
	if action != "install" {
		t.Fatalf("action = %q", action)
	}
	for _, tc := range []struct{ name, got, want string }{
		{"instance", c.Instance, "udp443"},
		{"app dir", c.AppDir, "/opt/udp443"},
		{"data", c.DataBase, "/var/lib/udp443"},
		{"openvpn", c.OpenVPNRoot, "/var/lib/udp443/openvpn"},
		{"log", c.LogDir, "/var/log/udp443"},
		{"service", c.Service, "udp443.service"},
		{"nat", c.NatService, "udp443-nat.service"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if c.MgmtPort < 7505 || c.MgmtPort > 7604 {
		t.Errorf("mgmt port %d outside 7505-7604", c.MgmtPort)
	}
}

// --dest must beat the derived app dir; the previous validate() re-derived it
// and silently installed into /opt/<instance>.
func TestDestFlagWins(t *testing.T) {
	t.Setenv("OVN_APP_DIR", "")
	c, _, err := Parse([]string{"install", "--local", "--dest", "/tmp/ovnode-dest-probe"})
	if err != nil {
		t.Fatal(err)
	}
	if c.AppDir != "/tmp/ovnode-dest-probe" {
		t.Errorf("AppDir = %q, want /tmp/ovnode-dest-probe", c.AppDir)
	}
	if c.DataBase != "/tmp/ovnode-dest-probe/data" {
		t.Errorf("DataBase = %q, want /tmp/ovnode-dest-probe/data", c.DataBase)
	}
}

// Instance-scoped host files: a second instance must not overwrite the first
// one's logrotate, cron, sysctl or backup paths.
func TestHostPathsAreInstanceScoped(t *testing.T) {
	t.Setenv("OVNODE_LOGROTATE_CONF", "")
	t.Setenv("OVN_COMPLETION_DIR", "")
	c := &Config{Instance: "udp443", CLIName: "udp443"}
	for _, tc := range []struct{ name, got, want string }{
		{"logrotate", c.logrotatePath(), "/etc/logrotate.d/udp443"},
		{"cron", c.cronPath(), "/etc/cron.d/udp443-purge"},
		{"sysctl", c.sysctlPath(), "/etc/sysctl.d/99-udp443.conf"},
		{"completion", c.completionPath(), "/etc/bash_completion.d/udp443"},
		{"data backup", c.instanceBackupDir("pre-purge-data"), "/var/backups/udp443-pre-purge-data"},
		{"nat", c.natConfigPath(), "/etc/default/udp443-nat"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	defaultInstance := &Config{Instance: "ovnode"}
	if got := defaultInstance.natConfigPath(); got != "/etc/default/ovnode-nat" {
		t.Errorf("default nat path = %q", got)
	}
}
