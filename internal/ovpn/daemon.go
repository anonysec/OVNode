// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"ovnode/internal/pki"
)

// SuperviseOpenVPN runs the OpenVPN daemon as a child of the agent process.
//
// Before there were two units (ovnode.service + ovnode-openvpn.service); both
// pointed at the same tree and both had to be restarted together. Now
// ovnode.service forks openvpn as a child and respawns it on exit — a single
// unit owns the whole lifecycle. Returns true when a config exists and the
// child was started; false otherwise.
func SuperviseOpenVPN(ctx context.Context) bool {
	conf := settingFile()
	if _, err := exec.LookPath("openvpn"); err != nil {
		return false
	}
	if _, err := os.Stat(conf); err != nil {
		return false
	}
	// Only run on the installed tree — a relocated/test tree manages its own
	// OpenVPN.
	if !pki.IsInstalledTree() {
		return false
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			started := time.Now()
			cmd := exec.Command("openvpn", "--config", conf)
			if err := cmd.Run(); err != nil {
				log.Printf("ovnode: openvpn child exited: %v", err)
			}
			// If it crashed instantly (<5s), don't hot-spin.
			if time.Since(started) < 5*time.Second {
				select {
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Second):
				}
			}
			fmt.Printf("ovnode: respawning openvpn\n")
		}
	}()
	return true
}
