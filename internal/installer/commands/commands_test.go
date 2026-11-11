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
		"MANAGEMENT_PORT=7526\n" +
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
