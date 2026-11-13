// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ovnode/internal/config"
	"ovnode/internal/settings"
	"ovnode/internal/store"
)

// purge-stale runs from cron without an OpenVPN setenv, so cfg.StatusFile is
// always the UDP file. It must still see a live TCP session and keep its
// marker.
func TestPurgeStaleKeepsLiveTCPMarker(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OpenVpnRoot", root)
	t.Setenv("DataDir", filepath.Join(root, "data"))
	t.Setenv("StatusFile", "")

	srv := settings.Defaults()
	srv.Protocol = settings.ProtoBoth
	state := filepath.Join(root, "data", "state")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(srv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "openvpn.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	header := "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID\n"
	udp := filepath.Join(root, "server", "udp")
	tcp := filepath.Join(root, "server", "tcp")
	for _, dir := range []string{udp, tcp} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(udp, "status.log"), []byte(header+"END\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tcpRow := "CLIENT_LIST,u1,9.9.9.9:5002,10.9.0.2,,,,0,0,,,,43,0\n"
	if err := os.WriteFile(filepath.Join(tcp, "status.log"), []byte(header+tcpRow+"END\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sessions := filepath.Join(root, "sessions")
	if err := os.MkdirAll(sessions, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(sessions, "u1.10.9.0.2")
	if err := store.WriteMarker(marker, store.Marker{
		CommonName: "u1", TrustedIP: "9.9.9.9", TrustedPort: "5002",
		PoolIP: "10.9.0.2", Created: time.Now().Add(-48 * time.Hour).Unix(),
		SessionID: "u1.10.9.0.2.1", ConnectedAt: time.Now().Add(-48 * time.Hour).Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	PurgeStale(config.Hook{SessionsDir: sessions, SessionTTL: 86400})
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("live TCP marker was removed: %v", err)
	}
}
