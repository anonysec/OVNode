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
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	t.Setenv("OVNODE_DATA_DIR", data)
	t.Setenv("OVNODE_USERS_DIR", filepath.Join(data, "users"))
	t.Setenv("OVNODE_SESSIONS_DIR", filepath.Join(data, "sessions"))
	t.Setenv("OVNODE_USAGE_DIR", filepath.Join(data, "usage"))
	t.Setenv("OVNODE_LOG_DIR", filepath.Join(dir, "logs"))
	t.Setenv("OVNODE_LOG_FILE", filepath.Join(dir, "logs", "events.log"))
	t.Setenv("OVNODE_RUNTIME_GROUP", "invalid-ovnode-fixture-group")
	t.Setenv("SSL_CERTFILE", filepath.Join(dir, "missing-cert"))
	t.Setenv("SSL_KEYFILE", filepath.Join(dir, "missing-key"))
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
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	t.Setenv("API_KEY", "0123456789abcdef0123456789abcdef") // 32 chars: no short-key gate
	t.Setenv("SSL_CERTFILE", filepath.Join(dir, "missing-cert"))
	if err := Run(); err == nil || !strings.Contains(err.Error(), "TLS cert") {
		t.Fatalf("manual TLS mode must reach its own TLS check: %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("API-only startup created a managed VPN tree: %v", err)
	}
}
