package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// InstallState values, identical to bash install_state_of output.
const (
	StateAbsent        = "absent"
	StateBootstrap     = "bootstrap"
	StateInstalled     = "installed"
	StateUnitOnly      = "unit-only"
	StateNodeData      = "node-data"
	StateNotADirectory = "not-a-directory"
	StateLocal         = "local"
)

// Config holds the OVN_* / flag inputs shared by every command.
type Config struct {
	AppDir      string
	DataBase    string
	OpenVPNRoot string
	LogDir      string
	MgmtPort    int

	Version string
	Repo    string

	Instance   string
	Service    string
	NatService string
	CLIName    string

	Port         string
	APIKey       string
	VPNPorts     string
	VPNSport     string
	ExtraPorts   string
	Proto        string
	NodeName     string
	TLSMethod    string
	TLSDomain    string
	TLSKey       string
	TLSCert      string
	PanelIP      string
	IPv6         bool
	NoNAT        bool
	Yes          bool
	Purge        bool
	Quiet        bool
	Local        bool
	SrcDir       string
	DestDir      string
	Pin          string
	RuntimeUser  string
	RuntimeGroup string
	PreState     string
}

// FromEnv builds a Config from OVN_* variables.
func FromEnv() *Config {
	c := &Config{
		Version:      envOr("Version", "latest"),
		Repo:         envOr("Repo", "anonysec/OVNode"),
		Port:         os.Getenv("ApiPort"),
		APIKey:       os.Getenv("ApiKey"),
		VPNPorts:     os.Getenv("VpnPorts"),
		Proto:        os.Getenv("Proto"),
		NodeName:     os.Getenv("NodeName"),
		TLSMethod:    envOr("TlsMethod", "selfsigned"),
		TLSDomain:    os.Getenv("TlsDomain"),
		TLSKey:       os.Getenv("TlsKey"),
		TLSCert:      os.Getenv("TlsCert"),
		PanelIP:      os.Getenv("PanelIp"),
		IPv6:         os.Getenv("Ipv6") == "1",
		NoNAT:        os.Getenv("NoNat") == "1",
		Yes:          os.Getenv("Yes") == "1",
		Purge:        os.Getenv("Purge") == "1",
		Quiet:        os.Getenv("Quiet") == "1",
		Local:        os.Getenv("Local") == "1",
		SrcDir:       os.Getenv("SrcDir"),
		DestDir:      os.Getenv("DestDir"),
		Pin:          os.Getenv("Version"),
		Instance:     os.Getenv("Instance"),
		RuntimeUser:  os.Getenv("RuntimeUser"),
		RuntimeGroup: os.Getenv("RuntimeGroup"),
	}
	c.finalize()
	return c
}

// finalize derives every path and name from the instance. It is idempotent
// and never overwrites an explicit value (flag or environment), so it can run
// once in FromEnv and again after the flags are parsed.
func (c *Config) finalize() {
	if c.Instance == "" {
		c.Instance = "ovnode"
	}
	if c.AppDir == "" {
		if v := envOr("AppDir", ""); v != "" {
			c.AppDir = v
		} else {
			c.AppDir = "/opt/" + c.Instance
		}
	}
	if c.DataBase == "" {
		if v := envOr("DataDir", ""); v != "" {
			c.DataBase = v
		} else {
			c.DataBase = "/var/lib/" + c.Instance
		}
	}
	if c.OpenVPNRoot == "" {
		if v := envOr("OpenVpnRoot", ""); v != "" {
			c.OpenVPNRoot = v
		} else {
			c.OpenVPNRoot = "/var/lib/" + c.Instance + "/openvpn"
		}
	}
	if c.LogDir == "" {
		if v := envOr("OVN_LOG_DIR", ""); v != "" {
			c.LogDir = v
		} else {
			c.LogDir = "/var/log/" + c.Instance
		}
	}
	// Management port: unique per instance to avoid conflicts on 127.0.0.1.
	if c.MgmtPort == 0 {
		if v := envOr("ManagementPort", ""); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 65535 {
				c.MgmtPort = n
			}
		}
	}
	if c.MgmtPort == 0 {
		// Hash instance name to a port in 7505..7604.
		h := 0
		for _, ch := range c.Instance {
			h = h*31 + int(ch)
		}
		c.MgmtPort = 7505 + (h % 100)
	}
	c.Service = c.Instance + ".service"
	c.NatService = c.Instance + "-nat.service"
	c.CLIName = c.Instance
}

// Host files the installer owns. Every one carries the instance name so a
// second instance never overwrites or removes the first one's files.
func (c *Config) logrotatePath() string {
	return envOr("LogrotateConf", "/etc/logrotate.d/"+c.Instance)
}
func (c *Config) sysctlPath() string { return "/etc/sysctl.d/99-" + c.Instance + ".conf" }
func (c *Config) cronPath() string   { return "/etc/cron.d/" + c.Instance + "-purge" }
func (c *Config) completionPath() string {
	return filepath.Join(envOr("CompletionDir", "/etc/bash_completion.d"), c.CLIName)
}
func (c *Config) instanceBackupDir(label string) string {
	return filepath.Join("/var/backups", c.Instance+"-"+label)
}

// AgentBin mirrors bash AGENT_BIN.
func (c *Config) AgentBin() string { return filepath.Join(c.AppDir, "ovnode-server") }

// InstallStateOf mirrors install_state_of.
func (c *Config) InstallStateOf(dir string) string {
	info, err := os.Lstat(dir)
	if err == nil && !info.IsDir() {
		return StateNotADirectory
	}
	if err != nil {
		if c.anyNodeUnit() {
			return StateUnitOnly
		}
		return StateAbsent
	}
	envPath := filepath.Join(dir, ".env")
	if _, err := os.Stat(envPath); err == nil {
		return StateInstalled
	}
	binPath := filepath.Join(dir, "ovnode")
	if st, err := os.Stat(binPath); err == nil && st.Mode().Perm()&0o111 != 0 {
		return StateInstalled
	}
	if c.anyNodeUnit() {
		return StateUnitOnly
	}
	dataDir := filepath.Join(dir, "data")
	if entries, _ := os.ReadDir(dataDir); len(entries) > 0 {
		return StateNodeData
	}
	return StateBootstrap
}

// NodeExists mirrors node_exists.
func (c *Config) NodeExists() bool {
	switch c.InstallStateOf(c.AppDir) {
	case StateInstalled, StateUnitOnly, StateNodeData:
		return true
	}
	return false
}

func (c *Config) anyNodeUnit() bool {
	sd := envOr("SystemdDir", "/etc/systemd/system")
	if _, err := os.Stat(filepath.Join(sd, "ovnode.service")); err == nil {
		return true
	}
	return false
}

// EnvGet mirrors lib.sh env_get.
func (c *Config) EnvGet(key string) string {
	path := filepath.Join(c.AppDir, ".env")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if idx := strings.IndexByte(line, '='); idx > 0 {
			if strings.TrimSpace(line[:idx]) == key {
				return strings.TrimSpace(strings.Trim(line[idx+1:], `"`))
			}
		}
	}
	return ""
}

// DataDir mirrors node_data_dir.
func (c *Config) DataDir() string {
	if v := c.EnvGet("DataDir"); v != "" {
		return v
	}
	return c.DataBase
}

// RefusePartialNode mirrors refuse_partial_node. It returns an error instead
// of exiting so the command layer, not the library, owns the process.
func (c *Config) RefusePartialNode() error {
	state := c.InstallStateOf(c.AppDir)
	var what, where, hint string
	if state == StateUnitOnly {
		what = "OVNode unit files"
		where = envOr("SystemdDir", "/etc/systemd/system")
		hint = "uninstall"
	} else {
		what = "node data"
		where = c.DataBase
		hint = "uninstall --purge"
		if st, _ := os.Stat(filepath.Join(c.AppDir, "data")); st != nil {
			where = filepath.Join(c.AppDir, "data")
		}
	}
	return alreadyInstalled("%s holds no node, but %s remains at %s; installing here would mint a second identity beside it. Finish that install instead: %s %s, or move it aside and re-run.",
		c.AppDir, what, where, os.Args[0], hint)
}

// ReportBootstrapDir mirrors report_bootstrap_dir.
func (c *Config) ReportBootstrapDir() {
	entries, _ := os.ReadDir(c.AppDir)
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	listing := strings.Join(names, " ")
	if listing == "" {
		listing = "empty"
	}
	if len(listing) > 160 {
		listing = listing[:157] + "..."
	}
	fmt.Fprintf(os.Stderr, "  %s holds no node (%s), treating it as an interrupted bootstrap\n", c.AppDir, listing)
	fmt.Fprintln(os.Stderr, "  Installing over it; nothing is deleted, and the previous contents stay listed above")
}
