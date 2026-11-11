// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunChecksRuntimePermissionsBeforeTLS(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "openvpn")
	data := filepath.Join(dir, "data")
	t.Setenv("OpenVpnRoot", root)
	t.Setenv("DataDir", data)
	t.Setenv("UsersDir", filepath.Join(data, "users"))
	t.Setenv("SessionsDir", filepath.Join(data, "sessions"))
	t.Setenv("UsageDir", filepath.Join(data, "usage"))
	t.Setenv("LogDir", filepath.Join(dir, "logs"))
	t.Setenv("LogFile", filepath.Join(dir, "logs", "events.log"))
	t.Setenv("RuntimeGroup", "invalid-ovnode-fixture-group")
	t.Setenv("TlsCertFile", filepath.Join(dir, "missing-cert"))
	t.Setenv("TlsKeyFile", filepath.Join(dir, "missing-key"))
	if err := os.MkdirAll(filepath.Join(root, "server", "pki", "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Run(); err == nil || !strings.Contains(err.Error(), "runtime permissions") {
		t.Fatalf("Run did not check runtime repair before TLS/service use: %v", err)
	}
}

func TestRunManualTLSDoesNotCreateVPNTree(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "unmanaged-openvpn")
	t.Setenv("OpenVpnRoot", root)
	t.Setenv("ApiKey", "0123456789abcdef0123456789abcdef") // 32 chars: no short-key gate
	t.Setenv("TlsCertFile", filepath.Join(dir, "missing-cert"))
	if err := Run(); err == nil || !strings.Contains(err.Error(), "TLS cert") {
		t.Fatalf("manual TLS mode must reach its own TLS check: %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("API-only startup created a managed VPN tree: %v", err)
	}
}
