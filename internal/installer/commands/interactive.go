// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Interactive asks for the install inputs on a terminal. Defaults come from
// the environment or flags; pressing Enter keeps them. The panel's same-server
// flow passes -y and the values it already asked for, so this runs only for a
// direct `bash install.sh` (or `ovnode install -i`).
func Interactive(c *Config) error {
	if !isTTY() {
		return &UsageError{"interactive install needs a terminal; use -y for an unattended install"}
	}
	reader := bufio.NewReader(os.Stdin)
	ask := func(label, def string) string {
		if def == "" {
			fmt.Fprintf(os.Stderr, "  %s: ", label)
		} else {
			fmt.Fprintf(os.Stderr, "  %s [%s]: ", label, def)
		}
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		return line
	}
	askBool := func(label string, def bool) bool {
		hint := "y/N"
		if def {
			hint = "Y/n"
		}
		value := strings.ToLower(ask(label+" ("+hint+")", ""))
		if value == "" {
			return def
		}
		return value == "y" || value == "yes" || value == "1" || value == "true"
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  Configuration (Enter keeps the bracketed default)")
	oldInstance := c.Instance
	c.Instance = ask("node name", c.Instance)
	if c.Instance != oldInstance {
		c.AppDir, c.DataBase, c.OpenVPNRoot, c.LogDir = "", "", "", ""
		c.MgmtPort = 0
	}
	c.Port = ask("API port", firstNonEmpty(c.Port, "2083"))
	c.APIKey = ask("API key (blank = generate)", c.APIKey)
	c.VPNPorts = ask("VPN ports", firstNonEmpty(c.VPNPorts, "1194"))
	c.Proto = ask("protocol (udp/tcp/both)", "both")
	c.TLSMethod = ask("TLS method (selfsigned/custom/letsencrypt)", firstNonEmpty(c.TLSMethod, "selfsigned"))
	switch c.TLSMethod {
	case "custom":
		c.TLSCert = ask("TLS certificate path", c.TLSCert)
		c.TLSKey = ask("TLS private key path", c.TLSKey)
	case "selfsigned":
		c.TLSDomain = ask("certificate SANs (comma-separated domains/IPs; blank = server,localhost)", c.TLSDomain)
	case "letsencrypt", "letsencrypt-ip":
		c.TLSDomain = ask("certificate domain or IP", c.TLSDomain)
	default:
		c.TLSMethod = "selfsigned"
		c.TLSDomain = ask("certificate SANs (comma-separated domains/IPs; blank = server,localhost)", c.TLSDomain)
	}
	c.IPv6 = askBool("IPv6 pool", c.IPv6)
	c.PanelIP = ask("panel IP/CIDR allowlist (blank = any)", c.PanelIP)
	c.finalize()

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  Summary")
	fmt.Fprintf(os.Stderr, "  Node     %s\n", c.Instance)
	fmt.Fprintf(os.Stderr, "  API      %s\n", c.Port)
	fmt.Fprintf(os.Stderr, "  VPN      %s %s\n", c.VPNPorts, c.Proto)
	fmt.Fprintf(os.Stderr, "  TLS      %s", c.TLSMethod)
	if c.TLSDomain != "" {
		fmt.Fprintf(os.Stderr, " (%s)", c.TLSDomain)
	}
	fmt.Fprintln(os.Stderr)
	if !askBool("install with these settings?", true) {
		return fmt.Errorf("aborted")
	}
	return nil
}

func firstNonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
