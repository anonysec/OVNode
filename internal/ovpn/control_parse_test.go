package ovpn

import (
	"strings"
	"testing"
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
