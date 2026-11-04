package ovpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChangeConfigMultiPortIdempotent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	t.Setenv("OVNODE_DATA_DIR", root+"/ovnode-data")
	serverDir := filepath.Join(root, "server")
	os.MkdirAll(serverDir, 0o755)
	conf := "port 1194\nproto udp\ndev tun\n"
	os.WriteFile(filepath.Join(serverDir, "server.conf"), []byte(conf), 0o644)
	tmpl := "client\ndev tun\nproto udp\nremote 10.0.0.1 1194\nverb 3\n"
	os.WriteFile(filepath.Join(serverDir, "client-common.txt"), []byte(tmpl), 0o644)

	req := ChangeConfigRequest{
		OVPNPort:      1194,
		Protocol:      "udp",
		TunnelAddress: "vpn.example.com",
		ExtraPorts:    "1195,1196",
	}
	var c1, c2 ChangeConfigResult
	if !ChangeConfig(req, &c1) {
		t.Fatal("first change failed")
	}
	first, _ := os.ReadFile(filepath.Join(serverDir, "client-common.txt"))
	if !strings.Contains(string(first), "remote vpn.example.com 1195") || !strings.Contains(string(first), "remote vpn.example.com 1196") {
		t.Fatalf("missing extra remote lines:\n%s", string(first))
	}
	if !ChangeConfig(req, &c2) {
		t.Fatal("second change failed")
	}
	second, _ := os.ReadFile(filepath.Join(serverDir, "client-common.txt"))
	if string(first) != string(second) {
		t.Fatalf("not idempotent:\nfirst:\n%s\nsecond:\n%s", string(first), string(second))
	}
}
