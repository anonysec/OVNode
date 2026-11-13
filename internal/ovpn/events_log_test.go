// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The OpenVPN log lives at server/<proto>/openvpn.log, not server/openvpn.log.
func TestOpenVPNLogEventsReadsPerProtocolLog(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OpenVpnRoot", root)
	t.Setenv("DataDir", filepath.Join(root, "data"))
	dir := filepath.Join(root, "server", "udp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Format("Mon Jan 2 15:04:05 2006")
	line := stamp + " [AF_INET]198.51.100.7:5000 TLS Error: TLS handshake failed\n"
	if err := os.WriteFile(filepath.Join(dir, "openvpn.log"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}

	if events := openvpnLogEvents(24); len(events) == 0 {
		t.Fatal("no TLS event from the per-protocol log")
	}
}
