// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"

	"ovnode/internal/fsx"
	"strconv"
	"strings"
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

func RuntimeUser() string  { return fsx.Env("RUNTIME_USER", "nobody") }
func RuntimeGroup() string { return fsx.Env("RUNTIME_GROUP", "nogroup") }
func ManagementPort() int  { return envInt("MANAGEMENT_PORT", 7505) }
func VPNNetwork() string   { return fsx.Env("VPN_NETWORK", "10.8.0.0") }
func VPNNetmask() string   { return fsx.Env("VPN_NETMASK", "255.255.255.0") }
func VPNDNS() (string, string) {
	return fsx.Env("VPN_DNS1", "1.1.1.1"), fsx.Env("VPN_DNS2", "8.8.8.8")
}
func MaxClients() int {
	n := envInt("MAX_CLIENTS", 250)
	if n < 1 {
		n = 250
	}
	return n
}
func IPv6Enabled() bool {
	v := strings.ToLower(fsx.Env("ENABLE_IPV6", "0"))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}
func IPv6Prefix() string { return fsx.Env("IPV6_PREFIX", "fd42:42:42:42::/64") }

// OpenVPNPort reads OPENVPN_PORT (not OVNODE_*) per Python.
func OpenVPNPort() int {
	if v, ok := os.LookupEnv("OPENVPN_PORT"); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 1194
}

func ExtraVPNPorts() []int {
	raw := fsx.Env("EXTRA_PORTS", "")
	// Python reads OVNODE_EXTRA_PORTS and OPENVPN_PORT separately.
	if v, ok := os.LookupEnv("OVNODE_EXTRA_PORTS"); ok {
		raw = v
	}
	primary := OpenVPNPort()
	out := []int{}
	seen := map[int]bool{}
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' }) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		n, err := strconv.Atoi(tok)
		if err != nil {
			continue
		}
		if n == primary || seen[n] {
			continue
		}
		if n < 1 || n > 65535 {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// Env is the generic accessor matching Python _env.
func Env(name, defaultVal string) string {
	if v, ok := os.LookupEnv("OVNODE_" + strings.ToUpper(name)); ok && v != "" {
		return v
	}
	return defaultVal
}
