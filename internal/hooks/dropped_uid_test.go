// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"ovnode/internal/fsx"
	"ovnode/internal/logging"
	"ovnode/internal/ovpn"
	"ovnode/internal/pki"
	"ovnode/internal/store"
)

func moduleRoot(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("module root not found")
		}
		dir = parent
	}
}

func TestHookConnectDroppedUID(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root required")
	}
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	dir, err := os.MkdirTemp("", "ovnode-runtime-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "ovnode")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/ovnode")
	build.Dir = moduleRoot(t)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	openvpnRoot := filepath.Join(dir, "vpn")
	dataDir := filepath.Join(dir, "data")
	appDir := filepath.Join(dir, "app")
	for _, d := range []string{
		filepath.Join(openvpnRoot, "server", "pki", "private"),
		filepath.Join(openvpnRoot, "server", "pki", "issued"),
		filepath.Join(openvpnRoot, "server", "udp"),
		filepath.Join(dataDir, "users"),
		filepath.Join(dataDir, "sessions"),
		filepath.Join(dataDir, "usage"),
		filepath.Join(dataDir, "log"), appDir, filepath.Join(dir, "var", "log"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("AppDir", appDir)
	t.Setenv("OpenVpnRoot", openvpnRoot)
	t.Setenv("DataDir", dataDir)
	t.Setenv("UsersDir", filepath.Join(dataDir, "users"))
	t.Setenv("SessionsDir", filepath.Join(dataDir, "sessions"))
	t.Setenv("UsageDir", filepath.Join(dataDir, "usage"))
	t.Setenv("LogDir", filepath.Join(dataDir, "log"))
	t.Setenv("LogFile", filepath.Join(dataDir, "log", "hook-events.log"))
	t.Setenv("RuntimeUser", "65533")
	t.Setenv("RuntimeGroup", "65533")
	cn := "droppeduser"
	if err := store.CreateUser(fsx.UsersDir(), cn); err != nil {
		t.Fatal(err)
	}
	if err := store.SetDisabled(fsx.UsersDir(), cn, false); err != nil {
		t.Fatal(err)
	}
	if err := store.SetLimit(fsx.UsersDir(), cn, 2); err != nil {
		t.Fatal(err)
	}
	if err := store.Lock(filepath.Join(fsx.SessionsDir(), ".lock."+cn), 0o660, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordSessionUsage(fsx.UsageDir(), cn, "api-created", 0, false); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		filepath.Join(fsx.UsersDir(), cn, "key.pem"):     "client-secret",
		filepath.Join(fsx.UsersDir(), cn, "client.ovpn"): "profile-secret",
		filepath.Join(pki.PKIDir(), "private", "ca.key"): "ca-secret",
		filepath.Join(appDir, ".env"):                    "ApiKey=private-fixture-key\n",
		pki.CRLFile():                                    "public-crl", ovpn.StatusFile(): "HEADER\tX\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if ovpn.EnsureMgmtPassword() == "" {
		t.Fatal("could not create fixture management password")
	}
	logFile := filepath.Join(dataDir, "log", "hook-events.log")
	logging.Event(logFile, "root-created event")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probeBin := filepath.Join(dir, "runtime-probe")
	binary, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(probeBin, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	repair := exec.CommandContext(ctx, exe, "-test.run=^TestHookRuntimeRepairProcess$")
	repair.Env = append(os.Environ(), "TestRUNTIME_JAIL="+dir)
	if output, err := repair.CombinedOutput(); err != nil {
		t.Fatalf("isolated permission repair: %v\n%s", err, output)
	}
	probe := exec.CommandContext(ctx, probeBin, "-test.run=^TestHookRuntimeAccessProcess$")
	probe.Env = append(os.Environ(), "TestRUNTIME_ACCESS=1")
	probe.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 65533}}
	if output, err := probe.CombinedOutput(); err != nil {
		t.Errorf("configured dropped UID access: %v\n%s", err, output)
	}
	unrelated := exec.CommandContext(ctx, probeBin, "-test.run=^TestHookUnrelatedUIDProcess$")
	unrelated.Env = append(os.Environ(), "TestRUNTIME_ACCESS=1")
	unrelated.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if output, err := unrelated.CombinedOutput(); err != nil {
		t.Errorf("unrelated UID exclusion: %v\n%s", err, output)
	}
	runHook := func(action, pool string, want int) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "/ovnode", "hook", action, cn)
		cmd.Env = append(os.Environ(), "common_name="+cn, "trusted_ip=198.51.100.1", "trusted_port=1000", "ifconfig_pool_remote_ip="+pool, "bytes_received=25", "bytes_sent=35")
		for index, value := range cmd.Env {
			key, path, ok := strings.Cut(value, "=")
			if ok && strings.HasPrefix(path, dir+"/") {
				cmd.Env[index] = key + "=" + strings.TrimPrefix(path, dir)
			}
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: dir, Credential: &syscall.Credential{Uid: 65533, Gid: 65533}}
		output, err := cmd.CombinedOutput()
		got := 0
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				got = exit.ExitCode()
			} else {
				t.Fatalf("hook fixture execution: %v\n%s", err, output)
			}
		}
		if got != want {
			log, _ := os.ReadFile(logFile)
			t.Fatalf("dropped-UID %s exit=%d, want %d: %s\n%s", action, got, want, output, log)
		}
	}
	runHook("connect", "10.66.0.2", 0)
	markerPath := filepath.Join(fsx.SessionsDir(), cn+".10.66.0.2")
	marker, ok := store.ReadMarker(markerPath)
	if !ok || marker.SessionID == "" {
		t.Fatal("real hook did not create a readable accounting marker")
	}
	if err := store.WriteMarker(markerPath, marker); err != nil {
		t.Fatal(err)
	}
	if err := store.SetLimit(fsx.UsersDir(), cn, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordSessionUsage(fsx.UsageDir(), cn, "api-created", 0, false); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(fsx.UsersDir(), cn, "state"), filepath.Join(fsx.UsageDir(), cn), markerPath} {
		info, err := os.Stat(path)
		want := os.FileMode(0o660)
		if strings.HasSuffix(path, "/state") {
			want = 0o640
		}
		if err != nil || info.Mode().Perm() != want || info.Sys().(*syscall.Stat_t).Gid != 65533 {
			t.Fatalf("atomic root API replacement lost runtime access: %s: %v (%v)", path, info, err)
		}
	}
	if err := os.Rename(logFile, logFile+".1"); err != nil {
		t.Fatal(err)
	}
	logging.Event(logFile, "root-created event after rotation")
	runHook("connect", "10.66.0.3", 0)
	log, err := os.ReadFile(logFile)
	if err != nil || !strings.Contains(string(log), "ALLOW session="+cn+".10.66.0.3") {
		t.Fatalf("dropped UID could not append after root log rotation: %q (%v)", log, err)
	}
	runHook("disconnect", "10.66.0.2", 0)
	usage, err := store.ReadUsageState(fsx.UsageDir(), cn)
	if err != nil || usage.Total != 60 {
		t.Fatalf("dropped UID final banking total=%d, want 60 (%v)", usage.Total, err)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatal("dropped UID could not remove the root-replaced marker")
	}
	state := filepath.Join(fsx.UsersDir(), cn, "state")
	if err := os.Chmod(state, 0o600); err != nil {
		t.Fatal(err)
	}
	runHook("connect", "10.66.0.4", 1)
	if err := os.Chmod(state, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte("limit=0\ndisabled=garbage\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	runHook("connect", "10.66.0.4", 1)
}
