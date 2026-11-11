// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"ovnode/internal/fsx"
	"ovnode/internal/pki"
	"ovnode/internal/store"
)

func TestEnsureMgmtPasswordPreservesRuntimeRead(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	t.Setenv("OVNODE_RUNTIME_GROUP", "65533")
	path := EnsureMgmtPassword()
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if got := EnsureMgmtPassword(); got != path {
		t.Fatalf("password path changed: %q", got)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("repair removed runtime-group read: %v (%v)", info, err)
	}
	if os.Geteuid() == 0 && info.Sys().(*syscall.Stat_t).Gid != 65533 {
		t.Fatalf("management password group=%d, want 65533", info.Sys().(*syscall.Stat_t).Gid)
	}
}

func TestEnsureMgmtPasswordAtomicReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required for configured ownership")
	}
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	t.Setenv("OVNODE_DATA_DIR", filepath.Join(dir, "data"))
	t.Setenv("OVNODE_LOG_DIR", filepath.Join(dir, "logs"))
	t.Setenv("OVNODE_LOG_FILE", filepath.Join(dir, "logs", "events.log"))
	t.Setenv("OVNODE_RUNTIME_GROUP", "65533")
	pki.EnsureDirTree()
	path := EnsureMgmtPassword()
	if err := store.FixRuntimePermissions(dir); err != nil {
		t.Fatal(err)
	}
	if err := fsx.WriteFileAtomic(path, []byte("replacement\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Sys().(*syscall.Stat_t).Gid != 65533 {
		t.Fatalf("atomic management replacement lost runtime ownership/access: %v (%v)", info, err)
	}
	if got := EnsureMgmtPassword(); got != path {
		t.Fatalf("replacement repair changed the management path: %q", got)
	}
}

func TestManagementReplacementIgnoresInstalledEnv(t *testing.T) {
	if jail := os.Getenv("OVNODE_TEST_INSTALLED_ENV_JAIL"); jail != "" {
		if err := syscall.Chroot(jail); err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir("/"); err != nil {
			t.Fatal(err)
		}
		t.Setenv("OVN_APP_DIR", "/missing-test-app")
		t.Setenv("TMPDIR", "/scratch")
		TestEnsureMgmtPasswordAtomicReplacement(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for isolated installed-env fixture")
	}
	jail := t.TempDir()
	for _, path := range []string{"opt/ovnode", "external", "scratch", "installed-vpn/server/pki/private", "installed-data/logs"} {
		if err := os.MkdirAll(filepath.Join(jail, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sentinel := filepath.Join(jail, "external", "management-pass")
	if err := os.WriteFile(sentinel, []byte("external-sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	installedEnv := "OVNODE_OPENVPN_ROOT=/installed-vpn\nOVNODE_DATA_DIR=/installed-data\nOVNODE_LOG_DIR=/installed-data/logs\nOVNODE_LOG_FILE=/installed-data/logs/events.log\nOVNODE_MGMT_PASS_FILE=/external/management-pass\nOVNODE_RUNTIME_GROUP=65533\n"
	if err := os.WriteFile(filepath.Join(jail, "opt/ovnode/.env"), []byte(installedEnv), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestManagementReplacementIgnoresInstalledEnv$")
	cmd.Env = append(os.Environ(), "OVNODE_TEST_INSTALLED_ENV_JAIL="+jail)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("installed-env fixture isolation failed: %v\n%s", err, output)
	}
	data, err := os.ReadFile(sentinel)
	info, statErr := os.Stat(sentinel)
	if err != nil || statErr != nil {
		t.Fatalf("sentinel read: %v; stat: %v", err, statErr)
	}
	if string(data) != "external-sentinel\n" || info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Gid != 0 {
		t.Fatalf("test inherited installed .env and changed an external sentinel: data=%q mode=%04o group=%d", data, info.Mode().Perm(), info.Sys().(*syscall.Stat_t).Gid)
	}
}

func TestRestartChecksPermissionsBeforeControl(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	t.Setenv("OVNODE_DATA_DIR", filepath.Join(dir, "data"))
	t.Setenv("OVNODE_RUNTIME_GROUP", "invalid-ovnode-fixture-group")
	pki.EnsureDirTree()
	if err := os.WriteFile(fsx.ServerConf(), []byte("dev tun\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if RestartOpenVPN() {
		t.Fatal("restart accepted an unrepairable runtime identity")
	}
}

func TestSecretRepairPreservesPolicyDirectoryAccess(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	t.Setenv("OVNODE_DATA_DIR", filepath.Join(dir, "data"))
	if err := store.CreateUser(fsx.UsersDir(), "alice"); err != nil {
		t.Fatal(err)
	}
	pki.EnsureSecretPerms()
	info, err := os.Stat(filepath.Join(fsx.UsersDir(), "alice"))
	if err != nil || info.Mode()&(os.ModePerm|os.ModeSetgid) != 0o750|os.ModeSetgid {
		t.Fatalf("secret repair reset policy directory access: %v (%v)", info, err)
	}
}

func TestManagementPortMatchesHookFallback(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_LOG_DIR", dir)
	t.Setenv("OVNODE_LOG_FILE", filepath.Join(dir, "events.log"))
	for _, port := range []string{"0", "65536", "invalid", "7506"} {
		t.Setenv("OVNODE_MANAGEMENT_PORT", port)
		want := 7505
		if port == "7506" {
			want = 7506
		}
		if got := ManagementPort(); got != want {
			t.Errorf("management port %q=%d, want hook fallback %d", port, got, want)
		}
	}
}

func TestFreshPKIDirectoryAllowsRuntimeTraversal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	pki.EnsureDirTree()
	info, err := os.Stat(fsx.PKIDir())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o011 == 0 {
		t.Fatalf("fresh PKI directory %04o prevents dropped-UID CRL traversal", info.Mode().Perm())
	}
	info, err = os.Stat(filepath.Join(fsx.PKIDir(), "private"))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("private key tree must stay private: %v (%v)", info, err)
	}
}

func TestHookEnvironmentExportsEffectiveOverrides(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	t.Setenv("OVNODE_DATA_DIR", filepath.Join(dir, "data"))
	t.Setenv("OVNODE_LOG_DIR", filepath.Join(dir, "logs"))
	t.Setenv("OVNODE_LOG_FILE", filepath.Join(dir, "logs", "custom.log"))
	t.Setenv("OVNODE_STATUS_FILE", filepath.Join(dir, "custom-status"))
	t.Setenv("OVNODE_MGMT_PASS_FILE", filepath.Join(dir, "custom-password"))
	t.Setenv("OVNODE_SESSION_TTL", "120")
	t.Setenv("OVNODE_ALLOW_REMOTE_MGMT", "1")
	t.Setenv("API_KEY", "private-fixture-api-key")
	got := strings.Join(HookEnvDirectives(), "\n")
	for key, value := range map[string]string{
		"OVNODE_STATUS_FILE": filepath.Join(dir, "custom-status"), "OVNODE_MGMT_PASS_FILE": filepath.Join(dir, "custom-password"),
		"OVNODE_LOG_DIR": filepath.Join(dir, "logs"), "OVNODE_LOG_FILE": filepath.Join(dir, "logs", "custom.log"), "OVNODE_SESSION_TTL": "120",
		"OVNODE_ALLOW_REMOTE_MGMT": "1",
	} {
		if !strings.Contains(got, "setenv "+key+" "+value) {
			t.Errorf("effective %s not exported: %s", key, got)
		}
	}
	if strings.Contains(got, "private-fixture-api-key") {
		t.Fatal("hook environment exported the API key")
	}
}

// TestHookTargetsPointAtTheGoBinary covers the stale marker file: a tree
// that still says "python" must not send server.conf back to the deleted
// bash hooks.
func TestHookTargetsPointAtTheGoBinary(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	t.Setenv("OVNODE_DATA_DIR", dir+"/ovnode-data")
	targets := HookTargets()
	for _, directive := range []string{"client-connect", "client-disconnect"} {
		target := targets[directive]
		if !strings.HasSuffix(target, "ovnode-server hook "+directive[len("client-"):]) &&
			!strings.HasSuffix(target, "agent hook "+directive[len("client-"):]) {
			t.Fatalf("%s points at %q, want the go binary", directive, target)
		}
		if strings.Contains(target, ".sh") {
			t.Fatalf("%s points at a deleted bash hook: %q", directive, target)
		}
	}
}

func TestFreshServerConfOnlyRealOptions(t *testing.T) {
	openvpn, err := exec.LookPath("openvpn")
	if err != nil {
		t.Skip("openvpn not installed")
	}
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	t.Setenv("OVNODE_DATA_DIR", dir+"/ovnode-data")
	os.MkdirAll(filepath.Join(dir, "server"), 0o755)
	os.MkdirAll(filepath.Join(dir, "ovnode-data"), 0o755)
	conf := FreshServerConf()
	out, _ := exec.Command(openvpn, "--help").Output()
	known := map[string]bool{}
	re := regexp.MustCompile(`(?m)^--([a-z0-9][a-z0-9-]*)`)
	for _, m := range re.FindAllStringSubmatch(string(out), -1) {
		known[m[1]] = true
	}
	for _, extra := range []string{"persist-key", "data-ciphers-fallback"} {
		known[extra] = true
	}
	for _, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := strings.Fields(line)[0]
		name = strings.TrimPrefix(name, "-")
		if !known[name] {
			t.Errorf("unknown directive: %s", name)
		}
	}
}

func TestFreshServerConfHasCRLVerify(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	t.Setenv("OVNODE_DATA_DIR", dir+"/ovnode-data")
	os.MkdirAll(filepath.Join(dir, "server"), 0o755)
	os.MkdirAll(filepath.Join(dir, "ovnode-data"), 0o755)
	conf := FreshServerConf()
	if !strings.Contains(conf, "crl-verify") {
		t.Fatal("missing crl-verify")
	}
	if !strings.Contains(conf, "duplicate-cn") {
		t.Fatal("missing duplicate-cn")
	}
}

func TestEnsureServerConfRepairsExactlyOwnedDirectives(t *testing.T) {
	for _, variation := range []string{"unrelated-repair", "one-hook", "obsolete-pair", "additional-obsolete", "duplicate-current", "stale-environment"} {
		t.Run(variation, func(t *testing.T) {
			providerTree(t)
			conf := FreshServerConf()
			hooks := HookTargets()
			connect := "client-connect \"" + hooks["client-connect"] + "\"\n"
			disconnect := "client-disconnect \"" + hooks["client-disconnect"] + "\"\n"
			switch variation {
			case "unrelated-repair":
				conf = strings.ReplaceAll(conf, "tls-version-min 1.3\n", "")
			case "one-hook":
				conf = strings.ReplaceAll(conf, disconnect, "")
			case "obsolete-pair":
				conf = strings.ReplaceAll(conf, connect, "client-connect \"/retired/connect\"\n")
				conf = strings.ReplaceAll(conf, disconnect, "client-disconnect \"/retired/disconnect\"\n")
			case "additional-obsolete":
				conf += "client-connect\t\"/retired/connect\"\nclient-disconnect \"/retired/disconnect\"\n"
			case "duplicate-current":
				conf += connect + disconnect
			case "stale-environment":
				conf += "setenv\tOVNODE_MANAGEMENT_PORT 1\n" + HookEnvDirectives()[0] + "\n"
			}
			operator := "# operator note\nsetenv OVNODE_OPERATOR_TAG keep-me\npush \"route 192.0.2.0 255.255.255.0\"\n"
			conf += operator
			if err := os.WriteFile(fsx.ServerConf(), []byte(conf), 0o644); err != nil {
				t.Fatal(err)
			}
			if !EnsureServerConf() {
				t.Error("repair reported no change")
			}
			got, err := os.ReadFile(fsx.ServerConf())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(got), operator) {
				t.Error("repair removed unrelated operator directives")
			}
			desired := append([]string{strings.TrimSpace(connect), strings.TrimSpace(disconnect), "user " + RuntimeUser(), "group " + RuntimeGroup()}, HookEnvDirectives()...)
			for _, want := range desired {
				key := strings.Fields(want)[0]
				if key == "setenv" {
					key += " " + strings.Fields(want)[1]
				}
				count := 0
				for _, line := range strings.Split(string(got), "\n") {
					fields := strings.Fields(line)
					if len(fields) == 0 {
						continue
					}
					lineKey := fields[0]
					if lineKey == "setenv" && len(fields) > 1 {
						lineKey += " " + fields[1]
					}
					if lineKey == key {
						count++
						if strings.TrimSpace(line) != want {
							t.Errorf("obsolete managed directive survived: %q", line)
						}
					}
				}
				if count != 1 {
					t.Errorf("%s count=%d, want exactly one", key, count)
				}
			}
			before, err := os.Stat(fsx.ServerConf())
			if err != nil {
				t.Fatal(err)
			}
			if EnsureServerConf() {
				t.Error("second repair was not a no-op")
			}
			after, err := os.Stat(fsx.ServerConf())
			if err != nil {
				t.Fatal(err)
			}
			second, err := os.ReadFile(fsx.ServerConf())
			if err != nil || !bytes.Equal(got, second) || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
				t.Errorf("no-op repair wrote server.conf: %v", err)
			}
		})
	}
}

// A changed port must replace the old management/setenv lines, not append a
// second pair. The previous "add if missing" merge left both, so hooks read a
// port the server was not listening on.
func TestEnsureServerConfReplacesStaleManagedLines(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	t.Setenv("OVNODE_DATA_DIR", filepath.Join(dir, "data"))
	t.Setenv("OVNODE_LOG_DIR", filepath.Join(dir, "log"))
	t.Setenv("OVNODE_MANAGEMENT_PORT", "7601")
	t.Setenv("OVNODE_RUNTIME_USER", "root")
	t.Setenv("OVNODE_RUNTIME_GROUP", "0")
	if err := os.MkdirAll(filepath.Join(dir, "server"), 0o755); err != nil {
		t.Fatal(err)
	}
	stale := "port 1194\nproto udp\n" +
		"management 127.0.0.1 7505 /old/pass\n" +
		"management 127.0.0.1 7505 /old/pass\n" +
		"setenv OVNODE_MANAGEMENT_PORT 7505\n" +
		"user stale\ngroup stale\n"
	if err := os.WriteFile(fsx.ServerConf(), []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := ensureServerConf()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("configuration with stale managed lines was reported unchanged")
	}
	data, err := os.ReadFile(fsx.ServerConf())
	if err != nil {
		t.Fatal(err)
	}
	conf := string(data)
	if got := strings.Count(conf, "\nmanagement "); got != 1 {
		t.Errorf("management lines = %d, want 1\n%s", got, conf)
	}
	if !strings.Contains(conf, "management 127.0.0.1 7601 ") {
		t.Errorf("management line does not carry the new port:\n%s", conf)
	}
	if !strings.Contains(conf, "setenv OVNODE_MANAGEMENT_PORT 7601") {
		t.Errorf("setenv does not carry the new port:\n%s", conf)
	}
	if strings.Contains(conf, "7505") {
		t.Errorf("stale port survived:\n%s", conf)
	}
	if !strings.Contains(conf, "user "+RuntimeUser()) || !strings.Contains(conf, "group "+RuntimeGroup()) {
		t.Errorf("runtime user/group were not refreshed:\n%s", conf)
	}
}
