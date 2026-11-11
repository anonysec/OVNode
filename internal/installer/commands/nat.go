package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (c *Config) setupNAT(r Runner) error {
	natEnabled := !c.NoNAT
	natConfigPath := c.natConfigPath()
	if natEnabled {
		if data, err := os.ReadFile(natConfigPath); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "VpnNatEnabled=") {
					v := strings.TrimSpace(strings.Trim(strings.TrimPrefix(line, "VpnNatEnabled="), `"`))
					if v == "0" || strings.EqualFold(v, "false") || strings.EqualFold(v, "no") {
						natEnabled = false
					}
				}
			}
		}
	}
	content := fmt.Sprintf("# OVNode NAT configuration (managed by install.sh)\nVpnNatEnabled=%d\nVpnPrimaryPort=%s\nVpnExtraPorts=%s\n", b2i(natEnabled), c.VPNSport, c.ExtraPorts)
	if err := os.MkdirAll("/etc/default", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(natConfigPath, []byte(content), 0o644); err != nil {
		return err
	}
	if !natEnabled {
		return nil
	}
	// sysctl
	sysctl := "net.ipv4.ip_forward = 1\n"
	if c.IPv6 {
		sysctl += "net.ipv6.conf.all.forwarding = 1\n"
	}
	if err := os.MkdirAll("/etc/sysctl.d", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(c.sysctlPath(), []byte(sysctl), 0o644); err != nil {
		return err
	}
	_ = r.Run("sysctl", "-p", c.sysctlPath())
	return r.Run(c.AgentBin(), "nat", "apply")
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (c *Config) setupLogrotate() error {
	if err := os.MkdirAll("/etc/logrotate.d", 0o755); err != nil {
		return err
	}
	// The OpenVPN children are supervised by the agent (no separate unit), so
	// the rotation signal goes straight to each child's PID. SIGHUP makes
	// OpenVPN reopen its log-append file.
	hookLog := filepath.Join(c.LogDir, "hook-events.log")
	content := fmt.Sprintf(`%[1]s/server/*/openvpn.log {
    size 10M
    rotate 3
    compress
    missingok
    notifempty
    postrotate
        for pidfile in %[1]s/server/*/ovnode.pid; do
            [ -f "$pidfile" ] && kill -HUP "$(cat "$pidfile")" 2>/dev/null || true
        done
    endscript
}

%[2]s {
    size 10M
    rotate 5
    compress
    missingok
    notifempty
    copytruncate
}
`, c.OpenVPNRoot, hookLog)
	if err := os.WriteFile(c.logrotatePath(), []byte(content), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  # %s\n", hookLog)
	return nil
}

func (c *Config) openFirewall(r Runner) {
	ports := []string{c.VPNSport}
	if c.ExtraPorts != "" {
		ports = append(ports, strings.Split(c.ExtraPorts, ",")...)
	}
	if err := r.Run("ufw", "status"); err == nil {
		_ = r.Run("ufw", "allow", c.Port+"/tcp")
		for _, p := range ports {
			_ = r.Run("ufw", "allow", p+"/udp")
			_ = r.Run("ufw", "allow", p+"/tcp")
		}
		return
	}
	if err := r.Run("firewall-cmd", "--state"); err == nil {
		_ = r.Run("firewall-cmd", "--permanent", "--add-port="+c.Port+"/tcp")
		for _, p := range ports {
			_ = r.Run("firewall-cmd", "--permanent", "--add-port="+p+"/udp")
			_ = r.Run("firewall-cmd", "--permanent", "--add-port="+p+"/tcp")
		}
		_ = r.Run("firewall-cmd", "--reload")
	}
}
