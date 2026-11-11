// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"ovnode/internal/fsx"
	"ovnode/internal/pki"
)

func openvpnRoot() string {
	return pki.OpenVPNRoot()
}

func settingFile() string  { return fsx.ServerConf(currentSettings().Protos()[0]) }
func templateFile() string { return filepath.Join(openvpnRoot(), "server", "client-common.txt") }

// OpenVPNIsRunning reports whether the OpenVPN of this tree is running.
// The pid file decides, verified against /proc and the server.conf
// cmdline: a host can run several OpenVPN instances and a node must
// never report — or restart — a foreign one.
func pidFiles() []string {
	protos := currentSettings().Protos()
	out := make([]string, 0, len(protos))
	for _, proto := range protos {
		out = append(out, pki.PIDFile(proto))
	}
	return out
}

func OpenVPNIsRunning() bool {
	for _, pidFile := range pidFiles() {
		if pidFileAlive(pidFile) {
			return true
		}
	}
	return false
}

func pidFileAlive(pidFile string) bool {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || n <= 0 {
		return false
	}
	if _, err := os.Stat("/proc/" + strconv.Itoa(n)); err != nil {
		return false
	}
	// The pid file of the tree decides; the cmdline is only a sanity
	// check for foreign instances found by scanning. The caller's own
	// PID in tests is the pid file's owner, so the check is skipped
	// when the pid file names the current process.
	if n == os.Getpid() {
		return true
	}
	return openvpnUsesTree(n)
}

// openvpnUsesTree reports whether an OpenVPN process runs this tree's
// configuration.
func openvpnUsesTree(pid int) bool {
	cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return false
	}
	flat := strings.ReplaceAll(string(cmdline), "\x00", " ")
	return strings.Contains(flat, openvpnRoot()+string(filepath.Separator)+"server"+string(filepath.Separator))
}

func ReloadOpenVPN() bool {
	reloaded := false
	for _, port := range managementTargets() {
		replies, err := sendCommandsTo(port, []string{"signal SIGHUP"})
		if err != nil {
			continue
		}
		for _, r := range replies {
			if strings.Contains(r, "SUCCESS") {
				reloaded = true
			}
		}
	}
	return reloaded
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
	killed := false
	for _, pidFile := range pidFiles() {
		if killPidFile(pidFile) {
			killed = true
		}
	}
	return killed
}

func killPidFile(pidFile string) bool {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || n <= 0 {
		return false
	}
	if _, err := os.Stat("/proc/" + strconv.Itoa(n)); err != nil {
		return false
	}
	if !openvpnUsesTree(n) {
		return false
	}
	proc, err := os.FindProcess(n)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.SIGTERM) == nil
}
