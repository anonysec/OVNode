package commands

import (
	"fmt"
	"os"
	"path/filepath"
)

func (c *Config) systemdDir() string { return envOr("SystemdDir", "/etc/systemd/system") }
func (c *Config) natConfigPath() string {
	if c.Instance == "" || c.Instance == "ovnode" {
		return "/etc/default/ovnode-nat"
	}
	return "/etc/default/" + c.Instance + "-nat"
}

func (c *Config) writeSystemdUnit(r Runner) error {
	content := fmt.Sprintf(`[Unit]
Description=OVNode OpenVPN Node Agent (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=%s
EnvironmentFile=%s/.env
ExecStart=%s serve
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
RuntimeDirectory=ovnode-openvpn
RuntimeDirectoryMode=0755
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=%s %s %s %s /run/ovnode-openvpn /tmp
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ProtectKernelTunables=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target
`, c.NodeName, c.AppDir, c.AppDir, c.AgentBin(), c.AppDir, c.OpenVPNRoot, c.DataBase, c.LogDir)
	path := filepath.Join(c.systemdDir(), c.Service)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	_ = systemctlDirect(r, "daemon-reload")
	_ = systemctlDirect(r, "enable", c.Service)
	return nil
}

func (c *Config) writeNatUnit(r Runner) error {
	content := fmt.Sprintf(`[Unit]
Description=OVNode native NAT
ConditionPathExists=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=-%s
ExecStart=%s nat apply
ExecStop=%s nat cleanup
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`, c.natConfigPath(), c.natConfigPath(), c.AgentBin(), c.AgentBin())
	path := filepath.Join(c.systemdDir(), c.NatService)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	_ = systemctlDirect(r, "daemon-reload")
	_ = systemctlDirect(r, "enable", c.NatService)
	return nil
}

func (c *Config) installAgentBinary() error {
	src := filepath.Join(c.AppDir, "ovnode")
	info, err := os.Stat(src)
	if err != nil || info.IsDir() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("the ovnode binary could not be installed")
	}
	dst := c.AgentBin()
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		return err
	}
	legacy := filepath.Join(c.AppDir, "agent")
	if legacy != dst {
		_ = os.Remove(legacy)
	}
	return nil
}

func (c *Config) installCLI() {
	src := filepath.Join(c.AppDir, "ovnode.sh")
	data, err := os.ReadFile(src)
	if err != nil {
		return
	}
	binDir := envOr("BinDir", "/usr/local/bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(binDir, c.CLIName), data, 0o755)
}

func (c *Config) removeCLI() {
	binDir := envOr("BinDir", "/usr/local/bin")
	_ = os.Remove(filepath.Join(binDir, c.CLIName))
	_ = os.Remove(c.completionPath())
}

// cronLine mirrors the ovnode-purge cron entry.
func (c *Config) writeCron() error {
	path := c.cronPath()
	line := fmt.Sprintf("0 3 * * * root %s hook purge-stale >/dev/null 2>&1\n", c.AgentBin())
	return os.WriteFile(path, []byte(line), 0o644)
}
