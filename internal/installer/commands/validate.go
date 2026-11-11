package commands

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrRoot mirrors check_root: a precondition, not a usage error.
var ErrRoot = errors.New("must run as root")

var (
	nodeNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	apiKeyRe   = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
	tlsPathRe  = regexp.MustCompile(`^[A-Za-z0-9/._-]+$`)
	ipv4Re     = regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$`)
	ipv6Re     = regexp.MustCompile(`^[0-9A-Fa-f:]+(/[0-9]{1,3})?$`)
)

// UsageError marks a validation failure (exit 2).
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

func isPort(s string) bool {
	if s == "" {
		return false
	}
	var n int
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
		n = n*10 + int(ch-'0')
	}
	return n >= 1 && n <= 65535
}

// validate mirrors validate_input.
func (c *Config) validate() error {
	if c.Port != "" && !isPort(c.Port) {
		return &UsageError{fmt.Sprintf("Invalid service port: '%s'", c.Port)}
	}
	if c.Port == "" {
		c.Port = "2083"
	}
	if c.VPNPorts == "" {
		c.VPNPorts = "1194"
	}
	// parse_vpn_ports
	parts := strings.Split(strings.ReplaceAll(c.VPNPorts, " ", ""), ",")
	seen := map[string]bool{}
	for _, p := range parts {
		if p == "" {
			continue
		}
		if !isPort(p) {
			return &UsageError{fmt.Sprintf("Invalid OpenVPN port: '%s'", p)}
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		if c.VPNSport == "" {
			c.VPNSport = p
		} else {
			if c.ExtraPorts == "" {
				c.ExtraPorts = p
			} else {
				c.ExtraPorts += "," + p
			}
		}
	}
	if c.VPNSport == "" {
		return &UsageError{"At least one OpenVPN port is required"}
	}
	if c.VPNSport == c.Port {
		return &UsageError{"OpenVPN port and service port must differ"}
	}
	proto := strings.ToLower(c.Proto)
	if proto == "" {
		proto = "udp"
	}
	switch proto {
	case "udp", "tcp":
	default:
		return &UsageError{fmt.Sprintf("Invalid transport '%s' (use udp or tcp)", c.Proto)}
	}
	c.Proto = proto
	if c.NodeName == "" {
		c.NodeName = c.Instance
		if c.NodeName == "" {
			c.NodeName = "ovnode"
		}
	}
	if !nodeNameRe.MatchString(c.NodeName) || strings.ContainsAny(c.NodeName, "\n\r") {
		return &UsageError{"Invalid node name"}
	}
	if c.APIKey == "" {
		c.APIKey = generateAPIKey()
	}
	if len(c.APIKey) < 16 {
		return &UsageError{"API key must be at least 16 characters (openssl rand -hex 32)"}
	}
	if len(c.APIKey) < 32 {
		fmt.Fprintln(stderr, "  warning: API key is shorter than 32 characters; use openssl rand -hex 32 for new nodes")
	}
	if !apiKeyRe.MatchString(c.APIKey) {
		return &UsageError{"Invalid API key: use only letters, digits, '.', '_', '~', '+', '/', '=', '-'"}
	}
	if c.PanelIP != "" && !ipv4Re.MatchString(c.PanelIP) && !ipv6Re.MatchString(c.PanelIP) {
		return &UsageError{fmt.Sprintf("Invalid panel IP or CIDR: '%s'", c.PanelIP)}
	}
	if c.TLSKey != "" && !tlsPathRe.MatchString(c.TLSKey) {
		return &UsageError{"Invalid TLS key path"}
	}
	if c.TLSCert != "" && !tlsPathRe.MatchString(c.TLSCert) {
		return &UsageError{"Invalid TLS cert path"}
	}
	if c.TLSMethod == "" {
		c.TLSMethod = "selfsigned"
	}
	switch c.TLSMethod {
	case "letsencrypt", "letsencrypt-ip", "selfsigned", "custom":
	case "none":
		return &UsageError{"Plain HTTP is not allowed, pick selfsigned (default), letsencrypt, letsencrypt-ip or custom"}
	default:
		return &UsageError{fmt.Sprintf("Invalid TLS method: '%s'", c.TLSMethod)}
	}
	if (c.TLSMethod == "letsencrypt" || c.TLSMethod == "letsencrypt-ip") && c.TLSDomain == "" {
		return &UsageError{"--tls-domain is required for Let's Encrypt"}
	}
	if c.TLSMethod == "custom" {
		if c.TLSKey == "" || c.TLSCert == "" {
			return &UsageError{"Custom TLS key/cert files not found"}
		}
	}
	return nil
}

func generateAPIKey() string {
	return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

func filepath2(a, b string) string { return a + "/" + b }

var stderr = GetStderr()
