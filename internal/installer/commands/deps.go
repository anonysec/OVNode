// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package commands

import (
	"fmt"
	"os"
	"os/exec"
)

// ensureDependencies installs the runtime the node cannot start without. A
// stock Debian/Ubuntu image has neither OpenVPN nor easy-rsa; the Go installer
// used to assume both, fail at `ca init`, and leave a partial tree behind.
// The legacy installer installed them, so restore that behaviour.
func ensureDependencies(r Runner) error {
	if dependenciesPresent() {
		return nil
	}
	if isFake() {
		return nil
	}
	// The debconf frontend can otherwise stop on the openvpn package's
	// "start at boot?" question while the installer has no tty.
	prev, had := os.LookupEnv("DEBIAN_FRONTEND")
	_ = os.Setenv("DEBIAN_FRONTEND", "noninteractive")
	defer func() {
		if had {
			_ = os.Setenv("DEBIAN_FRONTEND", prev)
		} else {
			_ = os.Unsetenv("DEBIAN_FRONTEND")
		}
	}()
	update, install, ok := packageManager(func(name string) bool {
		_, err := exec.LookPath(name)
		return err == nil
	})
	if !ok {
		return fmt.Errorf("openvpn and easy-rsa are missing; install them with your package manager")
	}
	fmt.Fprintln(os.Stderr, "  Installing OpenVPN and easy-rsa...")
	_ = r.Run(update[0], update[1:]...)
	args := append(append([]string{}, install[1:]...), "openvpn", "easy-rsa")
	if err := r.Run(install[0], args...); err != nil {
		return fmt.Errorf("install openvpn and easy-rsa: %w", err)
	}
	if !dependenciesPresent() {
		return fmt.Errorf("openvpn or easy-rsa is still missing after install")
	}
	fmt.Fprintln(os.Stderr, "  ok    OpenVPN and easy-rsa installed")
	return nil
}

func dependenciesPresent() bool {
	if _, err := exec.LookPath("openvpn"); err != nil {
		return false
	}
	_, err := os.Stat("/usr/share/easy-rsa")
	return err == nil
}

// packageManager returns the refresh and install commands for the host.
// has is injected so the distro matrix is testable without a container.
func packageManager(has func(string) bool) (update, install []string, ok bool) {
	switch {
	case has("apt-get"):
		return []string{"apt-get", "update", "-qq"}, []string{"apt-get", "install", "-y", "-qq"}, true
	case has("dnf"):
		return []string{"dnf", "-q", "makecache"}, []string{"dnf", "install", "-y", "-q"}, true
	case has("yum"):
		return []string{"yum", "-q", "makecache"}, []string{"yum", "install", "-y", "-q"}, true
	case has("pacman"):
		return []string{"pacman", "-Sy", "--noconfirm"}, []string{"pacman", "-S", "--noconfirm"}, true
	case has("apk"):
		return []string{"apk", "update", "-q"}, []string{"apk", "add", "-q"}, true
	}
	return nil, nil, false
}
