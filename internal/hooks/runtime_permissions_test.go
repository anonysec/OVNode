// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ovnode/internal/config"
	"ovnode/internal/store"
)

func TestHookRuntimeRepairProcess(t *testing.T) {
	jail := os.Getenv("OVNODE_TEST_RUNTIME_JAIL")
	if jail == "" {
		return
	}
	if err := syscall.Chroot(jail); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("/"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"OVN_APP_DIR", "OVNODE_OPENVPN_ROOT", "OVNODE_DATA_DIR", "OVNODE_USERS_DIR", "OVNODE_SESSIONS_DIR", "OVNODE_USAGE_DIR", "OVNODE_LOG_DIR", "OVNODE_LOG_FILE"} {
		if err := os.Setenv(key, strings.TrimPrefix(os.Getenv(key), jail)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.FixRuntimePermissions("/vpn"); err != nil {
		t.Fatal(err)
	}
}

func TestHookRuntimeAccessProcess(t *testing.T) {
	if os.Getenv("OVNODE_TEST_RUNTIME_ACCESS") == "" {
		return
	}
	cfg := config.HookFromEnv()
	cn := "droppeduser"
	if st, err := store.ReadUserState(cfg.UsersDir, cn); err != nil || st.Limit != 2 || st.Disabled {
		t.Errorf("runtime policy read: %+v (%v)", st, err)
	}
	for _, path := range []string{cfg.MgmtPassFile, filepath.Join(cfg.OpenVPNRoot, "server/pki/crl.pem")} {
		if data, err := os.ReadFile(path); err != nil || len(data) == 0 {
			t.Errorf("runtime public/management read %s: %v", path, err)
		}
	}
	for _, path := range []string{
		filepath.Join(cfg.UsersDir, cn, "key.pem"), filepath.Join(cfg.UsersDir, cn, "client.ovpn"),
		filepath.Join(cfg.OpenVPNRoot, "server/pki/private/ca.key"), filepath.Join(os.Getenv("OVN_APP_DIR"), ".env"),
	} {
		if _, err := os.ReadFile(path); err == nil {
			t.Errorf("runtime UID read protected secret %s", path)
		}
	}
	for _, dir := range []string{cfg.SessionsDir, cfg.UsageDir} {
		if err := store.Lock(filepath.Join(dir, ".lock."+cn), 0o660, func() error { return nil }); err != nil {
			t.Errorf("runtime could not acquire API-created lock in %s: %v", dir, err)
		}
	}
	state := filepath.Join(cfg.UsersDir, cn, "state")
	if f, err := os.OpenFile(state, os.O_WRONLY|os.O_APPEND, 0); err == nil {
		f.Close()
		t.Error("runtime UID can modify policy")
	}
	if err := store.SetDisabled(cfg.UsersDir, cn, true); err == nil {
		t.Error("runtime UID can replace root policy")
	}
}

func TestHookUnrelatedUIDProcess(t *testing.T) {
	if os.Getenv("OVNODE_TEST_RUNTIME_ACCESS") == "" {
		return
	}
	cfg := config.HookFromEnv()
	for _, dir := range []string{cfg.SessionsDir, cfg.UsageDir, cfg.LogDir} {
		path := filepath.Join(dir, ".unrelated-uid")
		if err := os.WriteFile(path, nil, 0o600); err == nil {
			os.Remove(path)
			t.Errorf("unrelated UID can plant a runtime file in %s", dir)
		}
	}
	if _, err := os.ReadFile(filepath.Join(cfg.UsersDir, "droppeduser", "state")); err == nil {
		t.Error("unrelated UID can read runtime policy")
	}
}
