// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// NodePublicIP returns this node's first non-loopback IPv4 address.
func NodePublicIP() string {
	out, err := exec.Command("hostname", "-I").Output()
	if err == nil {
		for _, addr := range strings.Fields(string(out)) {
			if !strings.HasPrefix(addr, "127.") && !strings.Contains(addr, ":") {
				return addr
			}
		}
	}
	// fallback
	h, _ := os.Hostname()
	addrs, _ := net.LookupHost(h)
	for _, a := range addrs {
		if !strings.HasPrefix(a, "127.") && !strings.Contains(a, ":") {
			return a
		}
	}
	return "127.0.0.1"
}

// RemoteLines builds one remote line per reachable port.
func RemoteLines(tunnelAddr string, primaryPort int) string {
	ports := []int{primaryPort}
	ports = append(ports, ExtraVPNPorts()...)
	lines := make([]string, 0, len(ports))
	for _, p := range ports {
		lines = append(lines, "remote "+tunnelAddr+" "+strconv.Itoa(p))
	}
	return strings.Join(lines, "\n")
}

func itoa(n int) string {
	// avoid import cycle; use strconv via local
	return itoaStr(n)
}
