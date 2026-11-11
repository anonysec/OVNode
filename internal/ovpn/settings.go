// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"strconv"
	"strings"

	"ovnode/internal/fsx"
	"ovnode/internal/settings"
)

// env reads an OVNODE_* env var with default, falling back to os env.
func envInt(name string, defaultVal int) int {
	v := fsx.Env(name, "")
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return n
}

// currentSettings reads the instance's settings file. A corrupt file falls
// back to the shipped defaults so the agent still starts; the panel surfaces
// the error through /sync/config.
func currentSettings() settings.Server {
	s, err := settings.Load()
	if err != nil {
		return settings.Defaults()
	}
	return s
}

func RuntimeUser() string  { return fsx.RuntimeUser() }
func RuntimeGroup() string { return fsx.RuntimeGroup() }
func ManagementPort() int {
	port := envInt("MANAGEMENT_PORT", 7505)
	if port < 1 || port > 65535 {
		return 7505
	}
	return port
}

// VPNNetwork returns the VPN client subnet base (e.g. "10.8.0.0"). When
// OVNODE_VPN_NETWORK is not set explicitly, a unique subnet is derived from
// the data dir + OpenVPN root so multiple instances on one host do not
// collide on the default OpenVPN subnet (10.8.0.0/24).
func VPNNetwork() string {
	if v := fsx.Env("VPN_NETWORK", ""); v != "" {
		return v
	}
	// backwards-compat default for the canonical single instance
	dataDir := fsx.OVNodeDir()
	root := fsx.OpenVPNRoot()
	canonical := "/var/lib/" + fsx.InstanceName()
	if dataDir == canonical && (root == "/etc/openvpn" || root == canonical+"/openvpn") {
		return "10.66.0.0"
	}
	// deterministic per-instance subnet in 10.8.1.0 .. 10.8.254.0
	h := 0
	for _, c := range dataDir + "|" + root {
		h = h*31 + int(c)
	}
	octet := (h % 253) + 1 // 1..253
	return "10.66." + strconv.Itoa(octet) + ".0"
}
func VPNNetmask() string { return fsx.Env("VPN_NETMASK", "255.255.255.0") }

// VPNSubnet returns the CIDR form used by NAT (e.g. "10.8.0.0/24").
func VPNSubnet() string {
	net := VPNNetwork()
	if !strings.HasSuffix(net, ".0") {
		return net + "/24"
	}
	return net + "/24"
}
func VPNDNS() (string, string) {
	s := currentSettings()
	return s.DNSPrimary, s.DNSSecondary
}
func MaxClients() int    { return currentSettings().MaxClients }
func IPv6Enabled() bool  { return currentSettings().IPv6Enabled }
func IPv6Prefix() string { return currentSettings().IPv6Prefix }

// OpenVPNPort is the primary listener port from the settings file.
func OpenVPNPort() int { return currentSettings().Port }

// ExtraVPNPorts are the additional listener ports, de-duplicated against the
// primary by the settings validation.
func ExtraVPNPorts() []int {
	s := currentSettings()
	out := make([]int, 0, len(s.ExtraPorts))
	for _, p := range s.ExtraPorts {
		if p != s.Port {
			out = append(out, p)
		}
	}
	return out
}

// Env is the generic accessor matching Python _env.
func Env(name, defaultVal string) string {
	return fsx.Env(name, defaultVal)
}
