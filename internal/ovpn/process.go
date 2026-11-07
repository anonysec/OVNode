// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"ovnode/internal/pki"
	"ovnode/internal/store"
)

func openvpnRoot() string {
	return pki.OpenVPNRoot()
}

func settingFile() string  { return filepath.Join(openvpnRoot(), "server", "server.conf") }
func templateFile() string { return filepath.Join(openvpnRoot(), "server", "client-common.txt") }

func OpenVPNIsRunning() bool {
	pids := openvpnPIDs()
	for _, pid := range pids {
		if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err == nil {
			return true
		}
	}
	return false
}

// openvpnPIDs returns the pids of the OpenVPN instances of this tree.
//
// The pid file of the tree decides; pgrep only counts an instance that
// runs this tree's server.conf. A host can run several OpenVPN instances
// and a node must never report — or restart — a foreign one.
func openvpnPIDs() []int {
	var pids []int
	pidFile := pki.PIDFile()
	if data, err := os.ReadFile(pidFile); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			pids = append(pids, n)
		}
	}
	out, _ := exec.Command("pgrep", "-x", "openvpn").Output()
	for _, t := range strings.Fields(string(out)) {
		n, err := strconv.Atoi(t)
		if err != nil {
			continue
		}
		if !openvpnUsesTree(n) {
			continue
		}
		pids = append(pids, n)
	}
	return pids
}

// openvpnUsesTree reports whether an OpenVPN process runs this tree's
// configuration.
func openvpnUsesTree(pid int) bool {
	cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return false
	}
	flat := strings.ReplaceAll(string(cmdline), "\x00", " ")
	return strings.Contains(flat, pki.ServerConf())
}

// TreeOpenVPNRunning reports whether the OpenVPN of this tree is running.
//
// The pid file of the tree decides: a host can run several OpenVPN
// instances, and a foreign one must never be mistaken for this node's.
func TreeOpenVPNRunning() bool {
	for _, pid := range openvpnPIDs() {
		if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err == nil {
			return true
		}
	}
	return false
}

func ReloadOpenVPN() bool {
	replies, err := SendCommands([]string{"signal SIGHUP"})
	if err != nil {
		return false
	}
	for _, r := range replies {
		if strings.Contains(r, "SUCCESS") {
			return true
		}
	}
	return false
}

// RestartOpenVPN restarts the OpenVPN of this tree.
//
// The agent owns the daemon lifecycle: it supervises openvpn as a child of
// ovnode.service (started in serve), so this function restarts it as a child
// directly (pid-file or management socket), not as a standalone unit.
func RestartOpenVPN() bool {
	if _, err := os.Stat(settingFile()); err != nil {
		return false
	}
	if err := store.FixRuntimePermissions(openvpnRoot()); err != nil {
		return false
	}
	pki.EnsureSecretPerms()
	if pki.IsInstalledTree() {
		// openvpn is a child of ovnode.service: kill the pid and let the
		// supervisor respawn it. systemctl restart of ovnode is the hard
		// fallback via the CLI.
		if RestartOpenVPNChild() {
			return true
		}
	}
	// Fall back to a management-socket SIGHUP for relocated trees.
	return ReloadOpenVPN()
}

// RestartOpenVPNChild kills the supervised OpenVPN child (via the pid file);
// the serve loop's Wait() reaps it and starts a fresh one. Returns false when
// there is no supervised child to restart.
func RestartOpenVPNChild() bool {
	pidFile := pki.PIDFile()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false
	}
	if _, err := os.Stat("/proc/" + strconv.Itoa(n)); err != nil {
		return false
	}
	proc, err := os.FindProcess(n)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.SIGTERM) == nil
}
