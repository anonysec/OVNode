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

func setupConfigTree(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	t.Setenv("OVNODE_DATA_DIR", root+"/ovnode-data")
	serverDir := filepath.Join(root, "server")
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := "port 1194\nproto udp\ndev tun\ntun-ipv6\nserver-ipv6 fd42:42:42:42::/64\n"
	if err := os.WriteFile(filepath.Join(serverDir, "server.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	tmpl := "client\ndev tun\nproto udp\nremote 10.0.0.1 1194\nverb 3\n"
	if err := os.WriteFile(filepath.Join(serverDir, "client-common.txt"), []byte(tmpl), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, serverDir
}

func TestChangeConfigValidationTable(t *testing.T) {
	cases := []struct {
		name string
		req  ChangeConfigRequest
		ok   bool
	}{
		{"valid", ChangeConfigRequest{OVPNPort: 1194, Protocol: "udp", TunnelAddress: "vpn.example.com"}, true},
		{"bad port", ChangeConfigRequest{OVPNPort: 0, Protocol: "udp"}, false},
		{"bad proto", ChangeConfigRequest{OVPNPort: 1194, Protocol: "foo"}, false},
		{"bad tunnel", ChangeConfigRequest{OVPNPort: 1194, Protocol: "udp", TunnelAddress: "a b"}, false},
		{"bad ipv6", ChangeConfigRequest{OVPNPort: 1194, Protocol: "udp", EnableIPv6: boolPtr(true), IPv6Prefix: strPtr("1.2.3.4")}, false},
		{"reserved extra", ChangeConfigRequest{OVPNPort: 1194, Protocol: "udp", ExtraPorts: "22"}, false},
		{"too many extras", ChangeConfigRequest{OVPNPort: 1194, Protocol: "udp", ExtraPorts: "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, serverDir := setupConfigTree(t)
			before, _ := os.ReadFile(filepath.Join(serverDir, "server.conf"))
			got := ChangeConfig(tc.req, nil)
			if got != tc.ok {
				t.Fatalf("got %v want %v", got, tc.ok)
			}
			after, _ := os.ReadFile(filepath.Join(serverDir, "server.conf"))
			if !tc.ok && string(before) != string(after) {
				t.Fatalf("invalid request changed server.conf")
			}
		})
	}
}

func boolPtr(b bool) *bool    { return &b }
func strPtr(s string) *string { return &s }
