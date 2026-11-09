package commands

import (
	"fmt"
	"os"
	"strings"
)

// Parse mirrors parse_args + main's pre-flight gates.
//
// Exit codes mirror the bash constants; unsupported forms are usage
// errors (2). The parser keeps the deprecated spellings working.
func Parse(args []string) (*Config, string, error) {
	c := FromEnv()
	action := "install"
	i := 0
	for i < len(args) {
		arg := args[i]
		i++
		switch arg {
		case "update", "uninstall", "recover-update", "repair-unit":
			action = arg
		case "help", "--help", "-h":
			return c, "help", nil
		case "--port":
			if i >= len(args) {
				return nil, "", fmt.Errorf("--port needs a value")
			}
			fmt.Fprintln(os.Stderr, deprecatedFlag("--port", "set OVN_PORT instead"))
			c.Port = args[i]
			i++
		case "-p", "--key":
			if i >= len(args) {
				return nil, "", fmt.Errorf("%s needs a value", arg)
			}
			fmt.Fprintln(os.Stderr, deprecatedFlag(arg, "set OVN_KEY instead"))
			fmt.Fprintln(os.Stderr, "  warning: API key on the command line is visible to other users (ps); prefer OVN_KEY=...")
			c.APIKey = args[i]
			i++
		case "-v", "--version":
			if i >= len(args) {
				return nil, "", fmt.Errorf("%s needs a value", arg)
			}
			c.Pin = args[i]
			i++
		case "-i", "interactive":
			action = "interactive"
		case "--vpn-ports", "--vpn-port":
			if i >= len(args) {
				return nil, "", fmt.Errorf("%s needs a value", arg)
			}
			fmt.Fprintln(os.Stderr, deprecatedFlag(arg, "set OVN_VPN_PORTS instead"))
			c.VPNPorts = args[i]
			i++
		case "--proto":
			if i >= len(args) {
				return nil, "", fmt.Errorf("--proto needs a value")
			}
			fmt.Fprintln(os.Stderr, deprecatedFlag("--proto", "set OVN_PROTO instead"))
			c.Proto = args[i]
			i++
		case "--name":
			if i >= len(args) {
				return nil, "", fmt.Errorf("--name needs a value")
			}
			fmt.Fprintln(os.Stderr, deprecatedFlag("--name", "set OVN_NAME instead"))
			c.NodeName = args[i]
			i++
		case "--instance":
			if i >= len(args) {
				return nil, "", fmt.Errorf("--instance needs a value")
			}
			c.Instance = args[i]
			if c.NodeName == "" {
				c.NodeName = args[i]
			}
			i++
		case "--tls":
			if i >= len(args) {
				return nil, "", fmt.Errorf("--tls needs a value")
			}
			fmt.Fprintln(os.Stderr, deprecatedFlag("--tls", "set OVN_TLS instead"))
			switch args[i] {
			case "1", "selfsigned":
				c.TLSMethod = "selfsigned"
			case "2", "letsencrypt":
				c.TLSMethod = "letsencrypt"
			case "3", "letsencrypt-ip":
				c.TLSMethod = "letsencrypt-ip"
			case "4", "custom":
				c.TLSMethod = "custom"
			default:
				return nil, "", fmt.Errorf("Invalid --tls '%s' (use 1, 2, 3 or 4)", args[i])
			}
			i++
		case "--tls-domain":
			if i >= len(args) {
				return nil, "", fmt.Errorf("--tls-domain needs a value")
			}
			fmt.Fprintln(os.Stderr, deprecatedFlag("--tls-domain", "set OVN_TLS_DOMAIN instead"))
			c.TLSDomain = args[i]
			i++
		case "--tls-key":
			if i >= len(args) {
				return nil, "", fmt.Errorf("--tls-key needs a value")
			}
			fmt.Fprintln(os.Stderr, deprecatedFlag("--tls-key", "set OVN_TLS_KEY instead"))
			c.TLSKey = args[i]
			i++
		case "--tls-cert":
			if i >= len(args) {
				return nil, "", fmt.Errorf("--tls-cert needs a value")
			}
			fmt.Fprintln(os.Stderr, deprecatedFlag("--tls-cert", "set OVN_TLS_CERT instead"))
			c.TLSCert = args[i]
			i++
		case "--local":
			c.Local = true
			if i < len(args) && !strings.HasPrefix(args[i], "-") {
				c.SrcDir = args[i]
				i++
			}
		case "--src":
			if i >= len(args) {
				return nil, "", fmt.Errorf("--src needs a value")
			}
			c.SrcDir = args[i]
			i++
		case "--dest":
			if i >= len(args) {
				return nil, "", fmt.Errorf("--dest needs a directory")
			}
			c.DestDir = args[i]
			i++
		case "--panel-ip":
			if i >= len(args) {
				return nil, "", fmt.Errorf("--panel-ip needs a value")
			}
			c.PanelIP = args[i]
			i++
		case "--ipv6":
			fmt.Fprintln(os.Stderr, deprecatedFlag("--ipv6", "set OVN_IPV6=1 instead"))
			c.IPv6 = true
		case "--no-nat":
			fmt.Fprintln(os.Stderr, deprecatedFlag("--no-nat", "set OVN_NO_NAT=1 instead"))
			c.NoNAT = true
		case "--yes", "-y":
			c.Yes = true
		case "--purge":
			fmt.Fprintln(os.Stderr, deprecatedFlag("--purge", "set OVN_PURGE=1 instead"))
			c.Purge = true
		case "--quiet", "-q":
			fmt.Fprintln(os.Stderr, deprecatedFlag(arg, "set OVN_QUIET=1 instead"))
			c.Quiet = true
		case "install":
			return nil, "", fmt.Errorf("'install' is the default, just drop the word")
		case "menu":
			return nil, "", fmt.Errorf("The menu lives in the manager, run: ovnode")
		case "status", "start", "stop", "restart", "restart-vpn", "logs", "backup", "auto-backup", "tls":
			return nil, "", fmt.Errorf("'%s' moved to the manager, use: ovnode %s", arg, arg)
		default:
			return nil, "", fmt.Errorf("Unknown option: %s (--help for usage)", arg)
		}
	}
	// Pin handling (main): validate then strip the leading v.
	if c.Pin != "" {
		if !validReleaseVersion(c.Pin) {
			return nil, "", fmt.Errorf("Bad --version '%s' (use 1.2.3, v1.2.3, 1.2.3-rc1)", c.Pin)
		}
		c.Version = strings.TrimPrefix(c.Pin, "v")
	}
	// Entry gates (parse_args): no bootstrap before the checks.
	switch action {
	case "uninstall":
		switch c.InstallStateOf(c.AppDir) {
		case StateInstalled, StateUnitOnly, StateNodeData:
		default:
			return nil, "", errNotInstalled(c.AppDir)
		}
	case "update", "recover-update", "repair-unit":
		if c.InstallStateOf(c.AppDir) != StateInstalled {
			return nil, "", errNotInstalled(c.AppDir)
		}
	}
	return c, action, nil
}

func errNotInstalled(appDir string) error {
	return fmt.Errorf("Not installed (%s has no node). Nothing was downloaded or changed.", appDir)
}

func deprecatedFlag(flag, what string) string {
	return fmt.Sprintf("  ⚠ %s is deprecated; %s", flag, what)
}

func validReleaseVersion(v string) bool {
	v = strings.TrimPrefix(v, "v")
	// MAJOR.MINOR.PATCH with optional suffix.
	main := strings.SplitN(v, "-", 2)[0]
	main = strings.SplitN(main, "+", 2)[0]
	parts := strings.Split(main, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
