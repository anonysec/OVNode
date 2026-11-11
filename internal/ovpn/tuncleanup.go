// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os/exec"
	"strings"
)

// CleanupStaleTunDevices removes leftover tun/ovpn devices that carry this
// instance's VPN gateway address. OpenVPN respawns can leave orphaned
// devices behind (each new process creates its own tunN when the previous
// one did not clean up), and several devices sharing one subnet break
// forwarding. Safe to call once at agent startup, before SuperviseOpenVPN.
func CleanupStaleTunDevices() {
	gw := strings.TrimSuffix(VPNNetwork(), ".0") + ".1"
	out, err := exec.Command("ip", "-o", "addr", "show").Output()
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		dev := strings.TrimSuffix(fields[1], ":")
		if !strings.HasPrefix(dev, "tun") {
			continue
		}
		for i := 0; i+1 < len(fields); i++ {
			if (fields[i] == "inet" || fields[i] == "inet6") && strings.HasPrefix(fields[i+1], gw+"/") {
				seen[dev] = true
			}
		}
	}
	for dev := range seen {
		_ = exec.Command("ip", "link", "del", "dev", dev).Run()
	}
}
