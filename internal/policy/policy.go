// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package policy holds the desired-state policy files (ports, DNS, IPv6)
// and their server.conf rewriters.
package policy

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"ovnode/internal/fsx"
)

func statePath(name string) string {
	return filepath.Join(fsx.OVNodeDir(), name)
}

// ── Ports ────────────────────────────────────────────────────────────

func PortsStatePath() string { return statePath("ports") }

func ParseExtraPorts(raw string, primary int) []int {
	out := []int{}
	seen := map[int]bool{}
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' }) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		n, err := strconv.Atoi(tok)
		if err != nil {
			continue
		}
		if n == primary || seen[n] {
			continue
		}
		if n < 1 || n > 65535 {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

type PortsState struct {
	Ports  []int
	Pinned bool
}

func ReadPortsState() PortsState {
	st := PortsState{}
	data, err := os.ReadFile(PortsStatePath())
	if err != nil {
		return st
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ports=") {
			continue
		}
		st.Pinned = true
		val := strings.TrimPrefix(line, "ports=")
		if val == "" {
			st.Ports = []int{}
			return st
		}
		st.Ports = ParseExtraPorts(val, 0)
	}
	return st
}

func WritePortsState(ports []int) bool {
	path := PortsStatePath()
	desired := "ports=" + joinInts(ports)
	// pinned empty list means explicitly cleared; write "ports=" for empty
	if len(ports) == 0 {
		desired = "ports="
	}
	if _, err := os.Stat(path); err == nil {
		old, _ := os.ReadFile(path)
		if strings.TrimSpace(string(old)) == desired {
			return false
		}
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ports-")
	if err != nil {
		return false
	}
	if tmp == nil {
		return false
	}
	tmp.WriteString(desired + "\n")
	tmp.Close()
	os.Chmod(tmp.Name(), 0o644)
	os.Rename(tmp.Name(), path)
	return true
}

func PortsEffective(defaultPorts []int) []int {
	st := ReadPortsState()
	if st.Pinned {
		return st.Ports
	}
	return defaultPorts
}

// SyncNATConfig updates /etc/default/ovnode-nat and executes ovnode-nat.sh apply
// so that iptables REDIRECT rules for extra ports take effect immediately.
func SyncNATConfig(primaryPort int, extraPorts []int) {
	natConf := "/etc/default/ovnode-nat"
	natScript := "/usr/local/sbin/ovnode-nat.sh"
	if _, err := os.Stat(natScript); err != nil {
		return
	}
	content := fmt.Sprintf("# OVNode NAT configuration\nVPN_PRIMARY_PORT=%d\nVPN_EXTRA_PORTS=%s\n", primaryPort, joinInts(extraPorts))
	_ = os.WriteFile(natConf, []byte(content), 0o644)
	_ = exec.Command(natScript, "apply").Run()
}

// ── DNS ──────────────────────────────────────────────────────────────

func DNSStatePath() string { return statePath("dns") }

type DNSState struct {
	DNS1 string
	DNS2 string
}

func ReadDNSState() DNSState {
	st := DNSState{}
	data, err := os.ReadFile(DNSStatePath())
	if err != nil {
		return st
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		if k == "dns1" {
			st.DNS1 = v
		}
		if k == "dns2" {
			st.DNS2 = v
		}
	}
	return st
}

func WriteDNSState(dns1, dns2 string) bool {
	path := DNSStatePath()
	var lines []string
	if dns1 != "" {
		lines = append(lines, "dns1="+dns1)
	}
	if dns2 != "" {
		lines = append(lines, "dns2="+dns2)
	}
	desired := strings.Join(lines, "\n")
	if _, err := os.Stat(path); err == nil {
		old, _ := os.ReadFile(path)
		if strings.TrimSpace(string(old)) == desired {
			return false
		}
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dns-")
	if err != nil {
		return false
	}
	if tmp == nil {
		return false
	}
	if desired != "" {
		tmp.WriteString(desired + "\n")
	}
	tmp.Close()
	os.Chmod(tmp.Name(), 0o644)
	os.Rename(tmp.Name(), path)
	return true
}

func DNSEffective(def1, def2 string) []string {
	st := ReadDNSState()
	v1 := st.DNS1
	if v1 == "" {
		v1 = def1
	}
	v2 := st.DNS2
	if v2 == "" {
		v2 = def2
	}
	out := []string{}
	if v1 != "" {
		out = append(out, v1)
	}
	if v2 != "" {
		out = append(out, v2)
	}
	return out
}

func ValidateIP(s string) string {
	ip := strings.TrimSpace(s)
	if ip == "" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

func ValidatePrefix(s string) string {
	candidate := strings.TrimSpace(s)
	if candidate == "" || !strings.Contains(candidate, "/") {
		return ""
	}
	_, ipnet, err := net.ParseCIDR(candidate)
	if err != nil || ipnet.IP.To4() != nil {
		return ""
	}
	return ipnet.String()
}

// ── IPv6 ─────────────────────────────────────────────────────────────

func IPv6StatePath() string { return statePath("ipv6") }

type IPv6State struct {
	Enabled string
	Prefix  string
}

func ReadIPv6State() IPv6State {
	st := IPv6State{}
	data, err := os.ReadFile(IPv6StatePath())
	if err != nil {
		return st
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		if k == "enabled" {
			st.Enabled = v
		}
		if k == "prefix" {
			st.Prefix = v
		}
	}
	return st
}

func WriteIPv6State(enabled bool, prefix string) bool {
	path := IPv6StatePath()
	en := "0"
	if enabled {
		en = "1"
	}
	desired := "enabled=" + en + "\nprefix=" + prefix
	if _, err := os.Stat(path); err == nil {
		old, _ := os.ReadFile(path)
		if strings.TrimSpace(string(old)) == desired {
			return false
		}
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ipv6-")
	if err != nil {
		return false
	}
	if tmp == nil {
		return false
	}
	tmp.WriteString(desired + "\n")
	tmp.Close()
	os.Chmod(tmp.Name(), 0o644)
	os.Rename(tmp.Name(), path)
	return true
}

func IPv6Effective(defEnabled bool, defPrefix string) (bool, string) {
	st := ReadIPv6State()
	enabled := defEnabled
	if v := strings.TrimSpace(st.Enabled); v != "" {
		vl := strings.ToLower(v)
		enabled = vl == "1" || vl == "true" || vl == "yes" || vl == "on"
	}
	prefix := defPrefix
	if v := strings.TrimSpace(st.Prefix); v != "" {
		prefix = v
	}
	return enabled, prefix
}

// ── Rewrite helpers (text) ───────────────────────────────────────────

// RewritePushDNS rewrites push dhcp-option DNS lines in conf.
func RewritePushDNS(conf string, servers []string) string {
	lines := strings.Split(conf, "\n")
	// remove existing push dhcp-option DNS
	var out []string
	for _, ln := range lines {
		if strings.Contains(ln, `push "dhcp-option DNS`) {
			continue
		}
		out = append(out, ln)
	}
	// insert after redirect-gateway or server
	idx := -1
	for i, ln := range out {
		if strings.Contains(ln, `push "redirect-gateway`) {
			idx = i
			break
		}
	}
	if idx < 0 {
		for i, ln := range out {
			if strings.HasPrefix(strings.TrimSpace(ln), "server ") {
				idx = i
				break
			}
		}
	}
	insert := []string{}
	for _, s := range servers {
		insert = append(insert, fmt.Sprintf(`push "dhcp-option DNS %s"`, s))
	}
	if idx >= 0 {
		newOut := []string{}
		newOut = append(newOut, out[:idx+1]...)
		newOut = append(newOut, insert...)
		newOut = append(newOut, out[idx+1:]...)
		out = newOut
	} else {
		out = append(out, insert...)
	}
	return strings.Join(out, "\n")
}

var _ = sort.Strings
var _ = regexp.MustCompile

func joinInts(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}
