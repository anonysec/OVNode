package commands

import (
	"fmt"
	"os"
	"path/filepath"
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

	Version string
	Repo    string

	Instance       string
	Service        string
	OpenVPNService string
	NatService     string
	CLIName        string

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
}

// FromEnv builds a Config from OVN_* variables.
func FromEnv() *Config {
	c := &Config{
		Version:      envOr("OVN_VERSION", "latest"),
		Repo:         envOr("OVN_REPO", "anonysec/OVNode"),
		Port:         os.Getenv("OVN_PORT"),
		APIKey:       os.Getenv("OVN_KEY"),
		VPNPorts:     os.Getenv("OVN_VPN_PORTS"),
		Proto:        os.Getenv("OVN_PROTO"),
		NodeName:     os.Getenv("OVN_NAME"),
		TLSMethod:    envOr("OVN_TLS", "selfsigned"),
		TLSDomain:    os.Getenv("OVN_TLS_DOMAIN"),
		TLSKey:       os.Getenv("OVN_TLS_KEY"),
		TLSCert:      os.Getenv("OVN_TLS_CERT"),
		PanelIP:      os.Getenv("OVN_PANEL_IP"),
		IPv6:         os.Getenv("OVN_IPV6") == "1",
		NoNAT:        os.Getenv("OVN_NO_NAT") == "1",
		Yes:          os.Getenv("OVN_YES") == "1",
		Purge:        os.Getenv("OVN_PURGE") == "1",
		Quiet:        os.Getenv("OVN_QUIET") == "1",
		Local:        os.Getenv("OVN_LOCAL") == "1",
		SrcDir:       os.Getenv("OVN_SRC_DIR"),
		DestDir:      os.Getenv("OVN_DEST_DIR"),
		Pin:          os.Getenv("OVN_VERSION"),
		Instance:     os.Getenv("OVN_INSTANCE"),
		RuntimeUser:  os.Getenv("OVN_RUNTIME_USER"),
		RuntimeGroup: os.Getenv("OVN_RUNTIME_GROUP"),
	}
	c.resolveDirs()
	if c.Instance == "" {
		c.Instance = "ovnode"
	}
	c.Service = c.Instance + ".service"
	c.OpenVPNService = c.Instance + "-openvpn.service"
	c.NatService = c.Instance + "-nat.service"
	c.CLIName = c.Instance
	return c
}

func (c *Config) resolveDirs() {
	if v := os.Getenv("OVN_APP_DIR"); v != "" {
		c.AppDir = v
	} else if c.Instance != "" {
		c.AppDir = "/opt/" + c.Instance
	} else {
		c.AppDir = "/opt/ovnode"
	}
	if v := os.Getenv("OVN_DATA_BASE"); v != "" {
		c.DataBase = v
	} else if c.Instance != "" {
		c.DataBase = "/var/lib/" + c.Instance
	} else {
		c.DataBase = "/var/lib/ovnode"
	}
	c.OpenVPNRoot = "/etc/openvpn"
}

// AgentBin mirrors bash AGENT_BIN.
func (c *Config) AgentBin() string { return filepath.Join(c.AppDir, "ovnode-server") }

// KeyFile mirrors bash release naming.
func (c *Config) keyFile() string { return "ovnode-linux-" + archName() }

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

// NodeIsInstalled mirrors node_is_installed.
func (c *Config) NodeIsInstalled() bool {
	return c.InstallStateOf(c.AppDir) == StateInstalled
}

func (c *Config) anyNodeUnit() bool {
	sd := envOr("OVN_SYSTEMD_DIR", "/etc/systemd/system")
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
	if v := c.EnvGet("DATA_DIR"); v != "" {
		return v
	}
	return c.DataBase
}

// RefusePartialNode mirrors refuse_partial_node.
func (c *Config) RefusePartialNode() {
	state := c.InstallStateOf(c.AppDir)
	var what, where, hint string
	if state == StateUnitOnly {
		what = "OVNode unit files"
		where = envOr("OVN_SYSTEMD_DIR", "/etc/systemd/system")
		hint = "uninstall"
	} else {
		what = "node data"
		where = c.DataBase
		hint = "uninstall --purge"
		if st, _ := os.Stat(filepath.Join(c.AppDir, "data")); st != nil {
			where = filepath.Join(c.AppDir, "data")
		}
	}
	fmt.Fprintf(os.Stderr, "\n  Error: %s holds no node, but %s remains at %s\n", c.AppDir, what, where)
	fmt.Fprintln(os.Stderr, "  Installing here would mint a second identity beside it. This run deletes neither.")
	fmt.Fprintf(os.Stderr, "  Finish that install instead: %s %s, or move it aside and re-run.\n\n", os.Args[0], hint)
	os.Exit(ExitAlready)
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
