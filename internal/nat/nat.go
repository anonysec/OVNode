package nat

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Config holds NAT parameters, loaded from /etc/default/ovnode-nat or env.
type Config struct {
	PrimaryPort int
	ExtraPorts  string
	Subnet      string
	TunDev      string
}

func LoadConfig() Config {
	cfg := Config{Subnet: "10.8.0.0/24", TunDev: "tun0"}
	// env overrides
	if v := os.Getenv("VPN_PRIMARY_PORT"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 {
			cfg.PrimaryPort = n
		}
	}
	if v := os.Getenv("VPN_EXTRA_PORTS"); v != "" {
		cfg.ExtraPorts = v
	}
	if v := os.Getenv("VPN_SUBNET"); v != "" {
		cfg.Subnet = v
	}
	if v := os.Getenv("VPN_TUN_DEV"); v != "" {
		cfg.TunDev = v
	}
	// conf file
	data, err := os.ReadFile("/etc/default/ovnode-nat")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			kv := strings.SplitN(line, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.TrimSpace(kv[0])
			val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
			switch key {
			case "VPN_PRIMARY_PORT":
				if n, _ := strconv.Atoi(val); n > 0 {
					cfg.PrimaryPort = n
				}
			case "VPN_EXTRA_PORTS":
				if cfg.ExtraPorts == "" {
					cfg.ExtraPorts = val
				}
			case "VPN_SUBNET":
				if cfg.Subnet == "10.8.0.0/24" {
					cfg.Subnet = val
				}
			case "VPN_TUN_DEV":
				if cfg.TunDev == "tun0" {
					cfg.TunDev = val
				}
			}
		}
	}
	return cfg
}

func defaultIface() string {
	out, _ := exec.Command("sh", "-c", "ip route show default 2>/dev/null | awk '{print $5; exit}'").Output()
	return strings.TrimSpace(string(out))
}

func rule(op, table, chain string, args ...string) {
	// check exists first for add
	if op == "add" {
		check := exec.Command("iptables", append([]string{"-t", table, "-C", chain}, args...)...)
		if check.Run() == nil {
			return // already present
		}
		add := exec.Command("iptables", append([]string{"-t", table, "-A", chain}, args...)...)
		add.Run()
		return
	}
	del := exec.Command("iptables", append([]string{"-t", table, "-D", chain}, args...)...)
	del.Run()
}

func Apply() error {
	cfg := LoadConfig()
	iface := defaultIface()
	if iface == "" {
		return fmt.Errorf("ovnode-nat: no default interface found")
	}
	rule("add", "nat", "POSTROUTING", "-o", iface, "-j", "MASQUERADE")
	// redirects
	if cfg.PrimaryPort > 0 && cfg.ExtraPorts != "" {
		for _, p := range strings.Fields(strings.ReplaceAll(cfg.ExtraPorts, ",", " ")) {
			for _, proto := range []string{"tcp", "udp"} {
				rule("add", "nat", "PREROUTING", "-p", proto, "--dport", p, "-j", "REDIRECT", "--to-ports", strconv.Itoa(cfg.PrimaryPort))
			}
		}
	}
	// forward rules via DOCKER-USER
	if out, _ := exec.Command("iptables", "-L", "DOCKER-USER", "-n").Output(); len(out) > 0 {
		rule("add", "filter", "DOCKER-USER", "-s", cfg.Subnet, "-i", cfg.TunDev, "-o", iface, "-j", "ACCEPT")
		rule("add", "filter", "DOCKER-USER", "-i", iface, "-o", cfg.TunDev, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	}
	return nil
}

func Cleanup() {
	cfg := LoadConfig()
	iface := defaultIface()
	if iface != "" {
		rule("del", "nat", "POSTROUTING", "-o", iface, "-j", "MASQUERADE")
	}
	if cfg.PrimaryPort > 0 && cfg.ExtraPorts != "" {
		for _, p := range strings.Fields(strings.ReplaceAll(cfg.ExtraPorts, ",", " ")) {
			for _, proto := range []string{"tcp", "udp"} {
				rule("del", "nat", "PREROUTING", "-p", proto, "--dport", p, "-j", "REDIRECT", "--to-ports", strconv.Itoa(cfg.PrimaryPort))
			}
		}
	}
	if iface != "" {
		rule("del", "filter", "DOCKER-USER", "-s", cfg.Subnet, "-i", cfg.TunDev, "-o", iface, "-j", "ACCEPT")
		rule("del", "filter", "DOCKER-USER", "-i", iface, "-o", cfg.TunDev, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	}
}
