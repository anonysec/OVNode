package commands

import (
	"fmt"
	"os"
	"ovnode/internal/fsx"
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
	// Preserved shape; RUNNER is the boundary for pkg_install.
	if err := os.MkdirAll("/etc/logrotate.d", 0o755); err != nil {
		return err
	}
	content := fmt.Sprintf("%s/server/*/openvpn.log {\n    size 10M\n    rotate 3\n    compress\n    missingok\n    notifempty\n    postrotate\n        systemctl kill -s HUP %s >/dev/null 2>&1 || true\n    endscript\n}\n", c.OpenVPNRoot, c.Service)
	path := c.logrotatePath()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	hookLog := c.EnvGet("LogFile")
	if hookLog == "" {
		if v := os.Getenv("LogFile"); v != "" {
			hookLog = v
		} else {
			hookLog = "/var/log/" + c.Instance + "/hook-events.log"
			if c.Instance == "" {
				hookLog = "/var/log/" + fsx.InstanceName() + "/hook-events.log"
			}
		}
	}
	group := c.RuntimeGroup
	if group == "" {
		group = "nogroup"
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
