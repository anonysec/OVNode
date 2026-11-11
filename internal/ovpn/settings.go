// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"strconv"
	"strings"

	"ovnode/internal/fsx"
	"ovnode/internal/settings"
)

// envInt reads an integer key with a default.
func envInt(name string, defaultVal int) int {
	v := fsx.Get(name, "")
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

// ManagementPort is the per-protocol management socket port. Each OpenVPN
// process owns one; the pair is deterministic so hooks and the agent agree
// without storing it.
func ManagementPort(proto string) int {
	if v := fsx.Get("ManagementPort", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 65535 {
			if proto == "tcp" && n < 65535 {
				return n + 1
			}
			return n
		}
	}
	h := 0
	for _, c := range fsx.InstanceName() + "/" + proto {
		h = h*31 + int(c)
	}
	return 7505 + h%100
}

// vpnPair returns the even third octet of the instance's /23. Both protocol
// servers live in that pair, so a second instance can never overlap either
// of them.
func vpnPair() int {
	if v := fsx.Get("VpnNetwork", ""); v != "" {
		if parts := strings.Split(v, "."); len(parts) == 4 {
			if n, err := strconv.Atoi(parts[2]); err == nil && n >= 0 && n <= 252 {
				return n - n%2
			}
		}
	}
	dataDir := fsx.OVNodeDir()
	root := fsx.OpenVPNRoot()
	canonical := "/var/lib/" + fsx.InstanceName()
	if dataDir == canonical && (root == "/etc/openvpn" || root == canonical+"/openvpn") {
		return 0
	}
	h := 0
	for _, c := range dataDir + "|" + root {
		h = h*31 + int(c)
	}
	return (h % 127) * 2
}

func vpnNetwork(octet int) string { return "10.66." + strconv.Itoa(octet) + ".0" }

// VPNNetwork is the instance's first /24.
func VPNNetwork() string { return vpnNetwork(vpnPair()) }

// VPNNetworkFor is the /24 a protocol server binds. With one protocol this is
// the instance network; with both, tcp takes the second /24 of the pair.
func VPNNetworkFor(proto string) string {
	if proto == "tcp" && currentSettings().Protocol == settings.ProtoBoth {
		return vpnNetwork(vpnPair() + 1)
	}
	return VPNNetwork()
}

func VPNNetmask() string { return "255.255.255.0" }

// VPNSubnet is the /23 that covers both protocol /24s, so NAT needs one rule
// per instance regardless of the protocol choice.
func VPNSubnet() string { return "10.66." + strconv.Itoa(vpnPair()) + ".0/23" }

func VPNDNS() (string, string) {
	s := currentSettings()
	return s.DNSPrimary, s.DNSSecondary
}
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

// Get is the generic accessor for keys that have no typed accessor yet.
func Get(name, defaultVal string) string { return fsx.Get(name, defaultVal) }
