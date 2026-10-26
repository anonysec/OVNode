// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ovnode/internal/pki"
)

// TestChangeConfigRequestBindsThePanelFields covers the json tags of the
// configuration request.
//
// Without them Go's case-insensitive matching leaves "ovpn_port" unbound:
// the panel's config push is a no-op that reports success, and the node
// never changes.
func TestChangeConfigRequestBindsThePanelFields(t *testing.T) {
	body := `{"tunnel_address":"vpn.example.com","protocol":"udp","ovpn_port":1195,` +
		`"set_new_setting":true,"dns1":"1.1.1.1","dns2":"8.8.8.8",` +
		`"enable_ipv6":true,"ipv6_prefix":"fd42::/64","extra_ports":"1196,1197"}`
	var req ChangeConfigRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	if req.OVPNPort == nil {
		t.Error("ovpn_port is unbound")
	}
	if req.Protocol != "udp" {
		t.Errorf("protocol = %q, want udp", req.Protocol)
	}
	if req.TunnelAddress != "vpn.example.com" {
		t.Errorf("tunnel_address = %q, want the pushed address", req.TunnelAddress)
	}
	if req.SetNewSetting == nil || !*req.SetNewSetting {
		t.Error("set_new_setting is unbound")
	}
	if req.DNS1 == nil || *req.DNS1 != "1.1.1.1" {
		t.Error("dns1 is unbound")
	}
	if req.DNS2 == nil || *req.DNS2 != "8.8.8.8" {
		t.Error("dns2 is unbound")
	}
	if req.EnableIPv6 == nil || !*req.EnableIPv6 {
		t.Error("enable_ipv6 is unbound")
	}
	if req.IPv6Prefix == nil || *req.IPv6Prefix != "fd42::/64" {
		t.Error("ipv6_prefix is unbound")
	}
	if req.ExtraPorts == nil {
		t.Error("extra_ports is unbound")
	}
}

// TestReadConfigReadsTheTree covers the drift detection the panel does.
//
// The paths follow the OpenVPN root, so a relocated tree is read from the
// relocated place.
func TestReadConfigReadsTheTree(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	serverDir := filepath.Join(root, "server")
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := "port 1195\nproto udp\ndev tun\ncrl-verify /etc/openvpn/server/pki/crl.pem\n"
	if err := os.WriteFile(filepath.Join(serverDir, "server.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	template := "client\ndev tun\nproto udp\nremote vpn.example.com 1195\n"
	if err := os.WriteFile(filepath.Join(serverDir, "client-common.txt"), []byte(template), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := ReadConfig()
	if cfg["port"] != 1195 {
		t.Errorf("port = %v, want 1195", cfg["port"])
	}
	if cfg["proto"] != "udp" {
		t.Errorf("proto = %v, want udp", cfg["proto"])
	}
	if cfg["tunnel_address"] != "vpn.example.com" {
		t.Errorf("tunnel_address = %v, want the remote of the template", cfg["tunnel_address"])
	}
}

// TestTreeOpenVPNRunningIgnoresForeignInstances covers the tree-scoped
// liveness check.
//
// A host can run several OpenVPN instances: a node that reports a foreign
// one as its own would restart it and kill the wrong sessions.
func TestTreeOpenVPNRunningIgnoresForeignInstances(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	serverDir := filepath.Join(root, "server")
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The pid file of the tree names a process that does not exist.
	if err := os.WriteFile(filepath.Join(serverDir, "ovnode.pid"), []byte("999999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if TreeOpenVPNRunning() {
		t.Fatal("a dead pid file reports a running OpenVPN")
	}
}

// TestRestartOpenVPNLeavesTheInstalledNodeAlone covers the tree-scoped
// restart.
//
// The service units point at the default OpenVPN root: a relocated tree that
// restarted them would bounce the installed node's tunnels.
func TestRestartOpenVPNLeavesTheInstalledNodeAlone(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	if pki.IsInstalledTree() {
		t.Fatal("the temporary tree is the installed one")
	}
	if RestartOpenVPN() {
		t.Fatal("a relocated tree restarted something")
	}
}

// TestSessionMarkersAreReadFromTheTree covers the marker reading.
//
// The lock files of the store are named like a marker but carry no session.
func TestSessionMarkersAreReadFromTheTree(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	sessionsDir := filepath.Join(root, "ovnode", "sessions")
	if err := os.MkdirAll(sessionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := "common_name=alice\ntrusted_ip=1.2.3.4\ntrusted_port=5678\n" +
		"ifconfig_pool_remote_ip=10.8.0.2\ncreated=1000\n"
	if err := os.WriteFile(filepath.Join(sessionsDir, "alice.10.8.0.2"), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionsDir, ".lock.alice"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	markers := readMarkers()
	if len(markers) != 1 {
		t.Fatalf("markers = %d, want 1", len(markers))
	}
	if markers[0].commonName != "alice" || markers[0].poolIP != "10.8.0.2" {
		t.Fatalf("the marker is %+v, want alice on 10.8.0.2", markers[0])
	}
}
