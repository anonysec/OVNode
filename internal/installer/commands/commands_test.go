// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package commands

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ovnode/internal/settings"
)

// TestParseMatchesBashContract pins the flag/env surfaces that Stage 2
// must preserve: OVN_* env mirrors every flag, CLI wins, deprecated
// spellings keep working, and the entry gates (uninstall/update on a
// box without a node) exit 4 without downloading anything.
func TestParseMatchesBashContract(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SystemdDir", t.TempDir())
	t.Setenv("AppDir", dir)
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
	t.Setenv("ApiPort", "8443")
	t.Setenv("ApiKey", "0123456789abcdef")
	t.Setenv("PanelIp", "198.51.100.7")
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
	t.Setenv("AppDir", dir)
	t.Setenv("DataDir", filepath.Join(dir, "data"))
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
	want := "Instance=ovnode\n" +
		"DataDir=" + filepath.Join(dir, "data") + "\n" +
		"OpenVpnRoot=/var/lib/ovnode/openvpn\n" +
		"LogDir=/var/log/ovnode\n" +
		"ApiPort=2083\n" +
		"ApiKey=0123456789abcdef0123456789abcdef\n" +
		"RuntimeUser=ovnode-vpn\n" +
		"RuntimeGroup=ovnode-vpn\n" +
		"LogLevel=info\n" +
		"ApiAllowedCidrs=203.0.113.9\n"
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
	t.Setenv("SystemdDir", t.TempDir())
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
	t.Setenv("AppDir", "")
	t.Setenv("DataDir", "")
	t.Setenv("OpenVpnRoot", "")
	t.Setenv("OVN_LOG_DIR", "")
	t.Setenv("Instance", "")
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
	t.Setenv("AppDir", "")
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
	t.Setenv("LogrotateConf", "")
	t.Setenv("CompletionDir", "")
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

// The example file is the documentation the installer points at. Every key it
// writes must be documented there, and the file must not document keys that
// no longer exist.
func TestEnvExampleMatchesWriter(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("read env.example: %v", err)
	}
	documented := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, _, ok := strings.Cut(line, "=")
		if ok {
			documented[strings.TrimSpace(k)] = true
		}
	}
	written := []string{
		"Instance", "DataDir", "OpenVpnRoot", "LogDir", "ApiPort", "ApiKey",
		"RuntimeUser", "RuntimeGroup", "LogLevel", "ApiAllowedCidrs",
		"TlsCertFile", "TlsKeyFile",
	}
	for _, key := range written {
		if !documented[key] {
			t.Errorf("%s is written by the installer but missing from env.example", key)
		}
		delete(documented, key)
	}
	for key := range documented {
		t.Errorf("env.example documents %s, which the installer no longer writes", key)
	}
}

// Install seeds the settings file from the flags; .env no longer carries any
// OpenVPN tuning.
func TestWriteSettingsSeedsTheModel(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AppDir", dir)
	t.Setenv("DataDir", filepath.Join(dir, "data"))
	cfg := &Config{
		Instance: "ovnode", AppDir: dir, DataBase: filepath.Join(dir, "data"),
		Port: "2083", APIKey: "0123456789abcdef", NodeName: "node",
		Proto: "both", VPNSport: "443", ExtraPorts: "8443", IPv6: true,
		RuntimeUser: "nobody", RuntimeGroup: "nogroup",
	}
	cfg.finalize()
	if err := cfg.writeSettings(); err != nil {
		t.Fatal(err)
	}
	s, err := settings.LoadFrom(filepath.Join(dir, "data", "state", "openvpn.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Protocol != "both" || s.Port != 443 {
		t.Fatalf("settings = protocol %q port %d", s.Protocol, s.Port)
	}
	if len(s.ExtraPorts) != 1 || s.ExtraPorts[0] != 8443 {
		t.Fatalf("extra ports = %v", s.ExtraPorts)
	}
	if !s.IPv6Enabled {
		t.Fatal("ipv6 flag was not seeded")
	}
}

// An update renames the staged tree over the app dir. Without .env and the
// scripts, systemd cannot load the environment file and the service fails.
func TestStageStaticAssetsCarriesEnvAndScripts(t *testing.T) {
	oldDir, stage := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(oldDir, ".env"), []byte("Instance=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "VERSION"), []byte("2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := stageStaticAssets(oldDir, stage); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".env", "VERSION", "install.sh", "ovnode.sh", "lib.sh"} {
		if _, err := os.Stat(filepath.Join(stage, name)); err != nil {
			t.Errorf("%s missing from the staged tree: %v", name, err)
		}
	}
}

// The scripts must come from the release being installed: a node updated from
// 2.0.0 to a newer build otherwise keeps the old operator CLI, which is how a
// fixed .env read stayed broken after the update that shipped it.
func TestStageStaticAssetsUsesTheStagedBinary(t *testing.T) {
	oldDir, stage := t.TempDir(), t.TempDir()
	script := "#!/bin/sh\n[ \"$1\" = assets ] && [ \"$2\" = write ] || exit 1\nprintf 'from-new\\n' > \"$4/lib.sh\"\n"
	if err := os.WriteFile(filepath.Join(stage, "ovnode"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := stageStaticAssets(oldDir, stage); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(stage, "lib.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "from-new\n" {
		t.Fatalf("lib.sh = %q, want the staged binary's copy", body)
	}
}

func TestStageStaticAssetsFailsWhenTheStagedBinaryCannotWrite(t *testing.T) {
	oldDir, stage := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(stage, "ovnode"), []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := stageStaticAssets(oldDir, stage); err == nil {
		t.Fatal("a staged binary that cannot write its assets must fail the update")
	}
}

func TestInstallIncompleteDetectsMissingCA(t *testing.T) {
	c := &Config{OpenVPNRoot: t.TempDir()}
	if !c.installIncomplete() {
		t.Fatal("a tree without a CA must be treated as a failed first install")
	}
	pkiDir := filepath.Join(c.OpenVPNRoot, "server", "pki")
	if err := os.MkdirAll(pkiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkiDir, "ca.crt"), []byte("ca"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c.installIncomplete() {
		t.Fatal("a tree with a CA is a complete install")
	}
	c2 := &Config{OpenVPNRoot: t.TempDir(), AppDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(c2.AppDir, installMarker), []byte("2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c2.installIncomplete() {
		t.Fatal("the completion marker makes a tree complete")
	}
}

func TestPrintCertificatePrintsOnlyThePEM(t *testing.T) {
	root := t.TempDir()
	c := &Config{OpenVPNRoot: root, AppDir: t.TempDir()}
	path := filepath.Join(root, "server", "pki", "issued", "server.crt")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "Certificate:\n    Data:\n        Version: 3\n-----BEGIN CERTIFICATE-----\nZGVy\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	c.printCertificate()
	_ = w.Close()
	os.Stderr = old
	out, _ := io.ReadAll(r)
	text := string(out)
	if !strings.Contains(text, "-----BEGIN CERTIFICATE-----") || !strings.Contains(text, "-----END CERTIFICATE-----") {
		t.Fatalf("PEM missing from summary: %s", text)
	}
	if strings.Contains(text, "Data:") {
		t.Fatalf("OpenSSL text leaked into summary: %s", text)
	}
	if !strings.Contains(text, "SHA256") {
		t.Fatalf("fingerprint missing: %s", text)
	}
}

// Every fresh install must get its own key; a constant placeholder would be
// shared by every node in the field.
func TestGenerateAPIKeyIsRandom(t *testing.T) {
	first := generateAPIKey()
	second := generateAPIKey()
	if len(first) != 64 {
		t.Fatalf("key length = %d, want 64 hex chars", len(first))
	}
	if !apiKeyRe.MatchString(first) {
		t.Fatalf("key %q does not match the accepted charset", first)
	}
	if first == second {
		t.Fatal("two keys are identical; the generator is not random")
	}
	if first == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatal("key is the old hardcoded placeholder")
	}
}
