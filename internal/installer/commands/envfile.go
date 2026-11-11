package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ovnode/internal/settings"
)

// writeEnv mirrors write_env: 0600, same keys, same order.
func (c *Config) writeEnv() error {
	if err := os.MkdirAll(c.AppDir, 0o755); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Instance=%s\n", c.Instance)
	fmt.Fprintf(&b, "DataDir=%s\n", c.DataDir())
	fmt.Fprintf(&b, "OpenVpnRoot=%s\n", c.OpenVPNRoot)
	fmt.Fprintf(&b, "LogDir=%s\n", c.LogDir)
	fmt.Fprintf(&b, "ApiPort=%s\n", c.Port)
	fmt.Fprintf(&b, "ApiKey=%s\n", c.APIKey)
	fmt.Fprintf(&b, "RuntimeUser=%s\n", c.RuntimeUser)
	fmt.Fprintf(&b, "RuntimeGroup=%s\n", c.RuntimeGroup)
	fmt.Fprintf(&b, "LogLevel=info\n")
	if c.TLSCert != "" {
		fmt.Fprintf(&b, "TlsCertFile=%s\n", c.TLSCert)
	}
	if c.TLSKey != "" {
		fmt.Fprintf(&b, "TlsKeyFile=%s\n", c.TLSKey)
	}
	if c.PanelIP != "" {
		fmt.Fprintf(&b, "ApiAllowedCidrs=%s\n", c.PanelIP)
	}
	path := filepath.Join(c.AppDir, ".env")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// writeSettings seeds state/openvpn.json from the install flags. The file is
// the runtime's single source of truth; .env only carries identity and paths.
func (c *Config) writeSettings() error {
	s := settings.Defaults()
	if proto, ok := settings.NormalizeProtocol(c.Proto); ok {
		s.Protocol = proto
	}
	if n, err := strconv.Atoi(c.VPNSport); err == nil {
		s.Port = n
	}
	s.ExtraPorts = nil
	for _, part := range strings.Split(c.ExtraPorts, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && n != s.Port {
			s.ExtraPorts = append(s.ExtraPorts, n)
		}
	}
	s.IPv6Enabled = c.IPv6
	if err := s.Validate(); err != nil {
		return err
	}
	return settings.SaveTo(filepath.Join(c.DataDir(), "state", "openvpn.json"), s)
}

// writeSetupInfo mirrors write_setup_info.
func (c *Config) writeSetupInfo(runner Runner) error {
	path := filepath.Join(c.DataDir(), "setup-info")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	scheme := "http"
	if c.TLSMethod != "none" {
		scheme = "https"
	}
	host := publicIP(runner)
	if host == "" {
		host = primaryIP(runner)
	}
	cert := c.TLSCert
	if cert == "" {
		cert = c.EnvGet("TlsCertFile")
	}
	var b strings.Builder
	b.WriteString("# OVNode connection details\n")
	fmt.Fprintf(&b, "Address: %s\n", host)
	fmt.Fprintf(&b, "Port: %s\n", c.Port)
	fmt.Fprintf(&b, "Protocol: %s\n", scheme)
	fmt.Fprintf(&b, "API Key: %s\n", c.APIKey)
	if cert != "" {
		if data, err := os.ReadFile(cert); err == nil {
			b.WriteString("Certificate:\n")
			b.Write(data)
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
