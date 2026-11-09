package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// writeEnv mirrors write_env: 0600, same keys, same order.
func (c *Config) writeEnv() error {
	if err := os.MkdirAll(c.AppDir, 0o755); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "NODE_NAME=%s\n", c.NodeName)
	fmt.Fprintf(&b, "DATA_DIR=%s\n", c.DataDir())
	fmt.Fprintf(&b, "OVNODE_DATA_DIR=%s\n", c.DataDir())
	fmt.Fprintf(&b, "SERVICE_PORT=%s\n", c.Port)
	fmt.Fprintf(&b, "API_KEY=%s\n", c.APIKey)
	fmt.Fprintf(&b, "OPENVPN_PORT=%s\n", c.VPNSport)
	proto := c.Proto
	if proto == "" {
		proto = "tcp"
	}
	fmt.Fprintf(&b, "OVNODE_PROTO=%s\n", proto)
	fmt.Fprintf(&b, "OVNODE_RUNTIME_USER=%s\n", c.RuntimeUser)
	fmt.Fprintf(&b, "OVNODE_RUNTIME_GROUP=%s\n", c.RuntimeGroup)
	fmt.Fprintf(&b, "TLS_METHOD=%s\n", c.TLSMethod)
	if c.ExtraPorts != "" {
		fmt.Fprintf(&b, "OVNODE_EXTRA_PORTS=%s\n", c.ExtraPorts)
	}
	if c.IPv6 {
		b.WriteString("OVNODE_ENABLE_IPV6=1\n")
	}
	if c.TLSCert != "" {
		fmt.Fprintf(&b, "SSL_CERTFILE=%s\n", c.TLSCert)
	}
	if c.TLSKey != "" {
		fmt.Fprintf(&b, "SSL_KEYFILE=%s\n", c.TLSKey)
	}
	if c.PanelIP != "" {
		fmt.Fprintf(&b, "OVNODE_PANEL_ALLOW=%s\n", c.PanelIP)
	}
	path := filepath.Join(c.AppDir, ".env")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// writeInstallResult mirrors write_install_result.
func (c *Config) writeInstallResult(path string, runner Runner) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	addr := primaryIP(runner)
	proto := "http"
	if c.TLSMethod != "none" {
		proto = "https"
	}
	cert := c.TLSCert
	if cert == "" {
		if v := os.Getenv("SSL_CERTFILE"); v != "" {
			cert = v
		} else {
			cert = filepath.Join(c.OpenVPNRoot, "server/pki/issued/server.crt")
		}
	}
	rows := []struct{ k, v string }{
		{"OVNODE_VERSION", c.Version},
		{"OVNODE_NAME", c.NodeName},
		{"OVNODE_API_PORT", c.Port},
		{"OVNODE_VPN_PORT", c.VPNSport},
		{"OVNODE_VPN_EXTRA_PORTS", c.ExtraPorts},
		{"OVNODE_VPN_PROTO", c.Proto},
		{"OVNODE_TLS_METHOD", c.TLSMethod},
		{"OVNODE_ADDRESS", addr},
		{"OVNODE_PROTOCOL", proto},
		{"OVNODE_API_KEY", c.APIKey},
		{"OVNODE_CERT_FILE", cert},
		{"OVNODE_DATA_DIR", c.DataDir()},
		{"OVNODE_SERVICE", c.Service},
	}
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "%s=%q\n", r.k, r.v)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
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
		cert = c.EnvGet("SSL_CERTFILE")
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
