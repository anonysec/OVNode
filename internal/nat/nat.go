package nat

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"ovnode/internal/ovpn"
)

// Config holds NAT parameters, loaded from /etc/default/ovnode-nat or env.
type Config struct {
	PrimaryPort int
	ExtraPorts  string
	Subnet      string
	TunDev      string
}

func LoadConfig() Config {
	cfg := Config{Subnet: ovpn.VPNSubnet(), TunDev: "tun0"}
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
				if cfg.Subnet == ovpn.VPNSubnet() {
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
	out, err := exec.Command("ip", "-o", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "dev" {
				iface := fields[i+1]
				if validIface(iface) {
					return iface
				}
			}
		}
	}
	return ""
}

func validIface(name string) bool {
	if len(name) < 1 || len(name) > 15 {
		return false
	}
	for _, c := range name {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func rule(op, table, chain string, args ...string) error {
	if op == "add" {
		check := exec.Command("iptables", append([]string{"-t", table, "-C", chain}, args...)...)
		if check.Run() == nil {
			return nil // already present
		}
		add := exec.Command("iptables", append([]string{"-t", table, "-A", chain}, args...)...)
		if err := add.Run(); err != nil {
			return fmt.Errorf("iptables add %s/%s: %w", table, chain, err)
		}
		return nil
	}
	del := exec.Command("iptables", append([]string{"-t", table, "-D", chain}, args...)...)
	if err := del.Run(); err != nil {
		return fmt.Errorf("iptables del %s/%s: %w", table, chain, err)
	}
	return nil
}

func Apply() error {
	cfg := LoadConfig()
	iface := defaultIface()
	flushOwnRedirects()
	if iface == "" {
		return fmt.Errorf("ovnode-nat: no default interface found")
	}
	if err := rule("add", "nat", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"); err != nil {
		return err
	}
	// redirects
	if cfg.PrimaryPort > 0 && cfg.ExtraPorts != "" {
		for _, p := range strings.Fields(strings.ReplaceAll(cfg.ExtraPorts, ",", " ")) {
			for _, proto := range []string{"tcp", "udp"} {
				if err := rule("add", "nat", "PREROUTING", "-p", proto, "--dport", p, "-m", "comment", "--comment", "ovnode-redirect", "-j", "REDIRECT", "--to-ports", strconv.Itoa(cfg.PrimaryPort)); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// flushOwnRedirects removes redirect rules previously created by this
// package, so a removed or changed extra port stops redirecting.
func flushOwnRedirects() {
	out, err := exec.Command("iptables", "-t", "nat", "-S", "PREROUTING").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "ovnode-redirect") {
			continue
		}
		if !strings.HasPrefix(line, "-A PREROUTING") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		fields[0] = "-D"
		_ = exec.Command("iptables", append([]string{"-t", "nat"}, fields...)...).Run()
	}
}

func Cleanup() {
	cfg := LoadConfig()
	iface := defaultIface()
	if iface != "" {
		_ = rule("del", "nat", "POSTROUTING", "-o", iface, "-j", "MASQUERADE")
	}
	if cfg.PrimaryPort > 0 && cfg.ExtraPorts != "" {
		for _, p := range strings.Fields(strings.ReplaceAll(cfg.ExtraPorts, ",", " ")) {
			for _, proto := range []string{"tcp", "udp"} {
				_ = rule("del", "nat", "PREROUTING", "-p", proto, "--dport", p, "-m", "comment", "--comment", "ovnode-redirect", "-j", "REDIRECT", "--to-ports", strconv.Itoa(cfg.PrimaryPort))
			}
		}
	}

}
