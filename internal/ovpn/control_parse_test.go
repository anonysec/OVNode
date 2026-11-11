package ovpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ovnode/internal/fsx"
	"ovnode/internal/pki"
	"ovnode/internal/settings"
)

func TestParseConfigRequestErrors(t *testing.T) {
	cases := []struct {
		name string
		req  ChangeConfigRequest
		want string
	}{
		{"missing port", ChangeConfigRequest{Protocol: "udp"}, "ovpn_port is required"},
		{"non-numeric port", ChangeConfigRequest{OVPNPort: "abc", Protocol: "udp"}, "ovpn_port is not a number"},
		{"port out of range", ChangeConfigRequest{OVPNPort: 70000, Protocol: "udp"}, "ovpn_port out of range"},
		{"port zero", ChangeConfigRequest{OVPNPort: 0, Protocol: "udp"}, "ovpn_port out of range"},
		{"extra port 22 is reserved", ChangeConfigRequest{OVPNPort: 22, Protocol: "udp"}, "ovpn_port is a reserved port"},
		{"bad proto", ChangeConfigRequest{OVPNPort: 1194, Protocol: "foo"}, "protocol must be tcp, udp or both"},
		{"bad tunnel", ChangeConfigRequest{OVPNPort: 1194, Protocol: "udp", TunnelAddress: "a b"}, "tunnel_address is malformed"},
		{"bad dns", ChangeConfigRequest{OVPNPort: 1194, Protocol: "udp", DNS1: strPtr("not-an-ip")}, "dns is not a valid IP"},
		{"bad ipv6", ChangeConfigRequest{OVPNPort: 1194, Protocol: "udp", EnableIPv6: boolPtr(true), IPv6Prefix: strPtr("1.2.3.4")}, "ipv6_prefix is not a valid prefix"},
		{"reserved extra", ChangeConfigRequest{OVPNPort: 1194, Protocol: "udp", ExtraPorts: "22"}, "extra port 22 is reserved"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfigRequest(tc.req)
			if err == nil {
				t.Fatalf("parseConfigRequest = nil error, want %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want containing %q", err.Error(), tc.want)
			}
		})
	}
}

func TestParseConfigRequestAcceptsNumberAndStringPorts(t *testing.T) {
	for _, port := range []any{1194, 1194.0, "1194"} {
		c, err := parseConfigRequest(ChangeConfigRequest{OVPNPort: port, Protocol: "udp"})
		if err != nil {
			t.Fatalf("port %v: %v", port, err)
		}
		if c.ovpnPort != 1194 {
			t.Fatalf("port %v decoded as %d, want 1194", port, c.ovpnPort)
		}
	}
}

func TestSettingsPatchAppliesEveryField(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OpenVpnRoot", root)
	t.Setenv("DataDir", filepath.Join(root, "data"))
	t.Setenv("RuntimeGroup", "0")
	t.Setenv("RuntimeUser", "root")
	if err := pki.EnsureDirTree(); err != nil {
		t.Fatal(err)
	}
	if err := settings.Save(settings.Defaults()); err != nil {
		t.Fatal(err)
	}
	proto, port, mssfix := "both", 443, 1350
	dns1, dns2 := "9.9.9.9", "1.0.0.1"
	maxClients := 500
	redirect := false
	res, err := applySettingsPatch(SettingsPatch{
		Protocol: &proto, Port: &port, Mssfix: &mssfix,
		DNSPrimary: &dns1, DNSSecondary: &dns2,
		MaxClients: &maxClients, RedirectGateway: &redirect,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.RestartRequired {
		t.Fatal("a protocol change must require a restart")
	}
	got, err := settings.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != "both" || got.Port != 443 || got.Mssfix != 1350 || got.MaxClients != 500 || got.RedirectGateway {
		t.Fatalf("settings not applied: %+v", got)
	}
	for _, proto := range []string{"udp", "tcp"} {
		if _, err := os.Stat(fsx.ServerConf(proto)); err != nil {
			t.Fatalf("%s configuration missing: %v", proto, err)
		}
	}
	conf, _ := os.ReadFile(fsx.ServerConf("tcp"))
	if !strings.Contains(string(conf), `push "dhcp-option DNS 9.9.9.9"`) {
		t.Fatalf("dns not rendered:\n%s", conf)
	}
	if strings.Contains(string(conf), `push "redirect-gateway`) {
		t.Fatal("redirect-gateway was not disabled")
	}
}

func TestSettingsPatchRejectsInvalidValue(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OpenVpnRoot", root)
	t.Setenv("DataDir", filepath.Join(root, "data"))
	if err := settings.Save(settings.Defaults()); err != nil {
		t.Fatal(err)
	}
	bad := 99999
	if _, err := applySettingsPatch(SettingsPatch{Port: &bad}); err == nil {
		t.Fatal("invalid port was accepted")
	}
	got, _ := settings.Load()
	if got.Port != 1194 {
		t.Fatalf("invalid patch changed the file: port %d", got.Port)
	}
}
