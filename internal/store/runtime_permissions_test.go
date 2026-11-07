// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRuntimePermissionRepairProcess(t *testing.T) {
	jail := os.Getenv("OVNODE_TEST_REPAIR_JAIL")
	if jail == "" {
		return
	}
	if err := syscall.Chroot(jail); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("/"); err != nil {
		t.Fatal(err)
	}
	if err := FixRuntimePermissions("/openvpn"); err != nil {
		t.Fatal(err)
	}
}

func runtimeRepairFixture(t *testing.T) string {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("root required for isolated permission repair")
	}
	dir, err := os.MkdirTemp("", "ovnode-repair-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"openvpn/server/pki/private", "data/users/alice", "data/sessions", "data/usage", "logs", "var/log"} {
		if err := os.MkdirAll(filepath.Join(dir, path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(dir, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func repairInJail(t *testing.T, dir string) ([]byte, error) {
	return repairCommand(t, dir).CombinedOutput()
}

func repairCommand(t *testing.T, dir string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestRuntimePermissionRepairProcess$")
	cmd.Env = append(os.Environ(),
		"OVNODE_TEST_REPAIR_JAIL="+dir, "OVN_APP_DIR=/app", "OVNODE_OPENVPN_ROOT=/openvpn",
		"OVNODE_DATA_DIR=/data", "OVNODE_USERS_DIR=/data/users", "OVNODE_SESSIONS_DIR=/data/sessions", "OVNODE_USAGE_DIR=/data/usage",
		"OVNODE_LOG_DIR=/logs", "OVNODE_LOG_FILE=/logs/events.log", "OVNODE_RUNTIME_USER=65533", "OVNODE_RUNTIME_GROUP=65533",
	)
	return cmd
}

func TestRuntimePermissionsRepairRelocatedPolicyAndSharedFiles(t *testing.T) {
	dir := runtimeRepairFixture(t)
	for path, body := range map[string]string{
		"data/users/alice/state": "limit=3\ndisabled=1\n", "data/users/alice/key.pem": "private",
		"data/users/alice/client.ovpn": "private", "data/sessions/.lock.alice": "", "data/usage/.lock.alice": "",
		"data/sessions/alice.10.66.0.2": "marker", "data/usage/alice": "10", "logs/events.log": "old event\n",
		"openvpn/server/mgmt-pass": "password", "openvpn/server/pki/crl.pem": "public",
	} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if output, err := repairInJail(t, dir); err != nil {
		t.Fatalf("permission repair failed: %v\n%s", err, output)
	}
	for path, want := range map[string]os.FileMode{
		"data/users/alice": 0o750 | os.ModeSetgid, "data/users/alice/state": 0o640,
		"data/sessions": 0o770 | os.ModeSetgid, "data/usage": 0o770 | os.ModeSetgid,
		"data/sessions/.lock.alice": 0o660, "data/usage/.lock.alice": 0o660,
		"data/sessions/alice.10.66.0.2": 0o660, "data/usage/alice": 0o660, "logs/events.log": 0o660,
		"openvpn/server/mgmt-pass": 0o640,
	} {
		info, err := os.Stat(filepath.Join(dir, path))
		if err != nil {
			t.Error(err)
			continue
		}
		if got := info.Mode() & (os.ModePerm | os.ModeSetgid); got != want {
			t.Errorf("%s mode=%v, want %v", path, got, want)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Uid != 0 || stat.Gid != 65533 {
			t.Errorf("%s owner=%d:%d, want 0:65533", path, stat.Uid, stat.Gid)
		}
	}
	for _, path := range []string{"data/users/alice/key.pem", "data/users/alice/client.ovpn"} {
		info, err := os.Stat(filepath.Join(dir, path))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("secret %s must stay 0600: %v (%v)", path, info, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "var/log/ovnode")); !os.IsNotExist(err) {
		t.Error("repair touched the default log path instead of the configured path")
	}
}

func TestRuntimePermissionsRejectSymlinkWithoutChangingTarget(t *testing.T) {
	dir := runtimeRepairFixture(t)
	target := filepath.Join(dir, "protected")
	if err := os.WriteFile(target, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/protected", filepath.Join(dir, "data/sessions/.lock.alice")); err != nil {
		t.Fatal(err)
	}
	if output, err := repairInJail(t, dir); err == nil {
		t.Errorf("repair accepted a planted shared-tree symlink: %s", output)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("repair changed the symlink target: %v (%v)", info, err)
	}
}

func TestRuntimePermissionsPreserveSharedLogSentinel(t *testing.T) {
	dir := runtimeRepairFixture(t)
	logDir := filepath.Join(dir, "logs")
	if err := os.Chmod(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(logDir, "unrelated-private-key")
	if err := os.WriteFile(sentinel, []byte("private-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "events.log"), []byte("owned event"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := repairInJail(t, dir); err != nil {
		t.Fatalf("shared log repair: %v\n%s", err, output)
	}
	for path, mode := range map[string]os.FileMode{logDir: 0o755, sentinel: 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if info.Mode()&(os.ModePerm|os.ModeSetgid) != mode || stat.Uid != 0 || stat.Gid != 0 {
			t.Errorf("shared log sentinel/parent was changed: %s mode=%v owner=%d:%d", path, info.Mode(), stat.Uid, stat.Gid)
		}
	}
	info, err := os.Stat(filepath.Join(logDir, "events.log"))
	if err != nil || info.Mode().Perm() != 0o660 || info.Sys().(*syscall.Stat_t).Gid != 65533 {
		t.Errorf("owned log was not repaired: %v (%v)", info, err)
	}
}

func TestRuntimeRepairRejectsNonRegularEntries(t *testing.T) {
	for _, name := range []string{"invalid-fifo", ".tmp-invalid-fifo", ".tmp-invalid-link"} {
		t.Run(name, func(t *testing.T) {
			dir := runtimeRepairFixture(t)
			path := filepath.Join(dir, "data", "sessions", name)
			var err error
			if strings.HasSuffix(name, "link") {
				err = os.Symlink("/missing", path)
			} else {
				err = syscall.Mkfifo(path, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if output, err := repairInJail(t, dir); err == nil {
				t.Fatalf("repair ignored a security-invalid entry %s: %s", name, output)
			}
		})
	}
}

func TestRuntimePermissionsRejectLegacyMapSymlink(t *testing.T) {
	dir := runtimeRepairFixture(t)
	if err := os.MkdirAll(filepath.Join(dir, "openvpn/clients"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "protected"), []byte(`{"alice":"private-name"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "openvpn/clients/uid_map.json")
	if err := os.Symlink("/protected", link); err != nil {
		t.Fatal(err)
	}
	if output, err := repairInJail(t, dir); err == nil {
		t.Errorf("repair followed a legacy map symlink: %s", output)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("repair consumed an untrusted legacy map: %v", err)
	}
}

func TestRuntimePermissionsNoManagedVPNTree(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", filepath.Join(dir, "openvpn"))
	t.Setenv("OVNODE_DATA_DIR", filepath.Join(dir, "data"))
	t.Setenv("OVNODE_LOG_DIR", filepath.Join(dir, "logs"))
	if err := FixRuntimePermissions(filepath.Join(dir, "openvpn")); err != nil {
		t.Errorf("API-only TLS mode must not require a managed VPN tree: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("permission repair created an unmanaged tree: %v (%v)", entries, err)
	}
}

func TestCheckedPolicyReadProcess(t *testing.T) {
	dir := os.Getenv("OVNODE_TEST_CHECKED_POLICY")
	if dir == "" {
		return
	}
	_, err := ReadUserState(dir, "alice")
	if wantError := os.Getenv("OVNODE_TEST_POLICY_ERROR") == "1"; (err != nil) != wantError {
		t.Fatalf("checked policy error=%v, want error=%v", err, wantError)
	}
}

func TestReadUserStateRejectsUnreadableMaterial(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root required to drop UID")
	}
	for _, kind := range []string{"directory", "state", "limit", "disabled", "disabled-directory", "disabled-dangling-symlink", "valid-default"} {
		t.Run(kind, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "ovnode-policy-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			userDir := filepath.Join(dir, "alice")
			if err := os.Mkdir(userDir, 0o755); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "directory":
				err = os.Chmod(userDir, 0o700)
			case "state", "limit", "disabled":
				body := ""
				if kind == "state" {
					body = "limit=0\ndisabled=1\n"
				} else if kind == "limit" {
					body = "2\n"
				}
				err = os.WriteFile(filepath.Join(userDir, kind), []byte(body), 0o600)
			case "disabled-directory":
				err = os.Mkdir(filepath.Join(userDir, "disabled"), 0o755)
			case "disabled-dangling-symlink":
				err = os.Symlink("missing", filepath.Join(userDir, "disabled"))
			}
			if err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			binary, err := os.ReadFile(exe)
			if err != nil {
				t.Fatal(err)
			}
			exe = filepath.Join(dir, "policy-reader")
			if err := os.WriteFile(exe, binary, 0o755); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestCheckedPolicyReadProcess$")
			wantError := "1"
			if kind == "valid-default" {
				wantError = "0"
			}
			cmd.Env = append(os.Environ(), "OVNODE_TEST_CHECKED_POLICY="+dir, "OVNODE_TEST_POLICY_ERROR="+wantError)
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 65533}}
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("dropped-UID checked read failed: %v\n%s", err, strings.TrimSpace(string(output)))
			}
		})
	}
}
