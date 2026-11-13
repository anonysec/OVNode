// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ovnode/internal/settings"
)

// One limit must count both transports. The hook used to receive a single
// StatusFile override, so StatusFiles() returned the same file twice and a
// live UDP session was invisible to a TCP connect.
func TestStatusSessionsReadsBothProtocols(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DataDir", dir)
	t.Setenv("OpenVpnRoot", filepath.Join(dir, "openvpn"))
	t.Setenv("StatusFile", "")

	srv := settings.Defaults()
	srv.Protocol = settings.ProtoBoth
	state := filepath.Join(dir, "state")
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
	rows := map[string]string{
		"udp": "CLIENT_LIST,u1,9.9.9.9:5001,10.8.0.2,,,,0,0,,,,42,0\n",
		"tcp": "CLIENT_LIST,u1,9.9.9.9:5002,10.9.0.2,,,,0,0,,,,43,0\n",
	}
	for proto, row := range rows {
		path := filepath.Join(dir, "openvpn", "server", proto)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "status.log"), []byte(header+row), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got := StatusSessionsForCN("", "u1")
	if len(got) != 2 {
		t.Fatalf("sessions = %d, want 2 (one per protocol): %+v", len(got), got)
	}
	protos := map[string]bool{}
	for _, s := range got {
		protos[s.Protocol] = true
	}
	if !protos["udp"] || !protos["tcp"] {
		t.Fatalf("protocols = %v, want udp and tcp", protos)
	}
}
