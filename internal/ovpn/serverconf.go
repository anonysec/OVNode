// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ovnode/internal/config"
	"ovnode/internal/fsx"
	"ovnode/internal/policy"
)

// HookTargets maps the client-connect/client-disconnect directives to the
// node's own binary.
func HookTargets() map[string]string {
	bin := fsx.AgentBin()
	return map[string]string{
		"client-connect":    bin + " hook connect",
		"client-disconnect": bin + " hook disconnect",
	}
}

func EnsureMgmtPassword() string {
	path := fsx.MgmtPassFile()
	uid, gid := os.Geteuid(), os.Getegid()
	if uid == 0 {
		var err error
		gid, err = fsx.RuntimeGroupID()
		if err != nil {
			return ""
		}
	}
	f, err := fsx.OpenFileNoFollow(path, os.O_RDONLY, 0)
	var data []byte
	if err == nil {
		data, err = io.ReadAll(f)
		f.Close()
	} else if !os.IsNotExist(err) {
		return ""
	}
	if err != nil && !os.IsNotExist(err) {
		return ""
	}
	if strings.TrimSpace(string(data)) == "" {
		if err := fsx.MkdirAllNoFollow(filepath.Dir(path), 0o755); err != nil {
			return ""
		}
		if err := fsx.WriteFileAtomic(path, []byte(randomHex(32)+"\n"), 0o640); err != nil {
			return ""
		}
	}
	if err := fsx.SetPermissions(path, 0o640, uid, gid); err != nil {
		return ""
	}
	return path
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	out := make([]byte, n*2)
	const hexd = "0123456789abcdef"
	for i := 0; i < n; i++ {
		out[i*2] = hexd[b[i]>>4]
		out[i*2+1] = hexd[b[i]&0x0f]
	}
	return string(out)
}

// MgmtLine returns the management directive.
func MgmtLine() string {
	port := ManagementPort()
	return fmt.Sprintf("management 127.0.0.1 %d %s", port, configValue(fsx.MgmtPassFile()))
}

func HardeningDirectives() []string {
	EnsureMgmtPassword()
	return []string{
		"tls-version-min 1.3",
		"remote-cert-tls client",
		MgmtLine(),
		"writepid " + fsx.PIDFile(),
		"script-security 2",
		"status-version 3",
	}
}

func FreshProto() string {
	choice := strings.ToLower(strings.TrimSpace(Env("PROTO", "tcp")))
	if strings.HasPrefix(choice, "udp") {
		return "udp"
	}
	return "tcp"
}

func ipv6Effective() (bool, string) {
	defEnabled := IPv6Enabled()
	defPrefix := IPv6Prefix()
	state := map[string]string{}
	data, err := os.ReadFile(filepath.Join(fsx.OVNodeDir(), "ipv6"))
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "=") {
				continue
			}
			k, v, _ := strings.Cut(line, "=")
			state[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	enabled := defEnabled
	if v, ok := state["enabled"]; ok {
		vl := strings.ToLower(strings.TrimSpace(v))
		enabled = vl == "1" || vl == "true" || vl == "yes" || vl == "on"
	}
	prefix := defPrefix
	if v, ok := state["prefix"]; ok && v != "" {
		prefix = v
	}
	return enabled, prefix
}

func FreshServerConf() string {
	if EnsureMgmtPassword() == "" {
		return ""
	}
	port := OpenVPNPort()
	proto := FreshProto()
	dns1, dns2 := VPNDNS()
	dnsServers := policy.DNSEffective(dns1, dns2)
	user := RuntimeUser()
	group := RuntimeGroup()
	ht := HookTargets()

	var lines []string
	lines = append(lines, "port "+itoaStr(port))
	lines = append(lines, "proto "+proto)
	lines = append(lines, "dev tun")
	lines = append(lines, "topology subnet")
	lines = append(lines, "server "+VPNNetwork()+" "+VPNNetmask())
	lines = append(lines, fmt.Sprintf("ifconfig-pool-persist %s 600", filepath.Join(fsx.OpenVPNRoot(), "server", "ipp.txt")))
	lines = append(lines, `push "redirect-gateway def1 bypass-dhcp"`)
	for _, s := range dnsServers {
		lines = append(lines, fmt.Sprintf(`push "dhcp-option DNS %s"`, s))
	}
	lines = append(lines, `push "block-outside-dns"`)

	enabled, prefix := ipv6Effective()
	if enabled {
		lines = append(lines, "tun-ipv6")
		lines = append(lines, "server-ipv6 "+prefix)
		lines = append(lines, `push "route-ipv6 2000::/3"`)
	}
	lines = append(lines, "keepalive 10 60")
	lines = append(lines, "ca "+fsx.CACert())
	lines = append(lines, "cert "+fsx.ServerCert())
	lines = append(lines, "key "+filepath.Join(fsx.PKIDir(), "private", "server.key"))
	lines = append(lines, "dh none")
	lines = append(lines, "tls-crypt "+fsx.TLSKey())
	lines = append(lines, "tls-version-min 1.3")
	lines = append(lines, "remote-cert-tls client")
	lines = append(lines, "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305")
	lines = append(lines, "data-ciphers-fallback AES-256-GCM")
	lines = append(lines, "auth SHA256")
	lines = append(lines, "mssfix 1360")
	lines = append(lines, "tun-mtu 1500")
	lines = append(lines, "sndbuf 393216")
	lines = append(lines, "rcvbuf 393216")
	lines = append(lines, "allow-compression no")
	lines = append(lines, "user "+user)
	lines = append(lines, "group "+group)
	// Export non-secret effective hook settings to the dropped-UID hooks via
	// OpenVPN setenv directives, so they do not need to read the private .env.
	lines = append(lines, HookEnvDirectives()...)
	lines = append(lines, "persist-key")
	lines = append(lines, "persist-tun")
	lines = append(lines, "script-security 2")
	// Quote the hook path because it contains a space ("ovnode hook connect")
	lines = append(lines, "client-connect \""+ht["client-connect"]+"\"")
	lines = append(lines, "client-disconnect \""+ht["client-disconnect"]+"\"")
	lines = append(lines, "client-config-dir "+filepath.Join(fsx.OpenVPNRoot(), "ccd"))
	lines = append(lines, "crl-verify "+fsx.CRLFile())
	lines = append(lines, "status "+configValue(fsx.StatusFile())+" 5")
	lines = append(lines, "status-version 3")
	lines = append(lines, MgmtLine())
	lines = append(lines, "writepid "+fsx.PIDFile())
	lines = append(lines, "log-append "+filepath.Join(fsx.OpenVPNRoot(), "server", "openvpn.log"))
	lines = append(lines, "cd "+filepath.Join(fsx.OpenVPNRoot(), "server"))

	lines = append(lines, HardeningDirectives()...)

	lines = append(lines, "max-clients "+itoaStr(MaxClients()))
	lines = append(lines, "explicit-exit-notify "+map[bool]string{true: "1", false: "0"}[proto == "udp"])
	lines = append(lines, "duplicate-cn")

	return strings.Join(lines, "\n") + "\n"
}

func EnsureServerConf() bool {
	changed, _ := ensureServerConf()
	return changed
}

func ensureServerConf() (bool, error) {
	if EnsureMgmtPassword() == "" {
		return false, fmt.Errorf("management password unavailable at %s", fsx.MgmtPassFile())
	}
	if _, err := os.Lstat(fsx.ServerConf()); os.IsNotExist(err) {
		data := FreshServerConf()
		if data == "" {
			return false, fmt.Errorf("server configuration could not be generated")
		}
		if err := fsx.WriteFileAtomic(fsx.ServerConf(), []byte(data), 0o644); err != nil {
			return false, err
		}
		return true, nil
	} else if err != nil {
		return false, err
	}
	data, err := os.ReadFile(fsx.ServerConf())
	if err != nil {
		return false, err
	}
	existing := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		existing[strings.TrimSpace(line)] = true
	}
	var toAdd []string
	ht := HookTargets()
	for _, d := range HardeningDirectives() {
		if !existing[d] {
			toAdd = append(toAdd, d)
		}
	}
	for _, d := range []string{"duplicate-cn"} {
		if !existing[d] {
			toAdd = append(toAdd, d)
		}
	}
	crl := "crl-verify " + fsx.CRLFile()
	if !existing[crl] {
		toAdd = append(toAdd, crl)
	}
	hookLines := []string{
		"client-connect \"" + ht["client-connect"] + "\"",
		"client-disconnect \"" + ht["client-disconnect"] + "\"",
	}
	runtimeLines := []string{"user " + RuntimeUser(), "group " + RuntimeGroup()}
	desiredHookLines := append([]string{}, hookLines...)
	desiredHookLines = append(desiredHookLines, HookEnvDirectives()...)
	desiredHookLines = append(desiredHookLines, runtimeLines...)
	if len(toAdd) == 0 && hooksAlreadyCurrent(string(data), desiredHookLines) {
		return false, nil
	}
	owned := map[string]bool{}
	for _, line := range desiredHookLines {
		owned[directiveKey(line)] = true
	}
	outLines := []string{}
	for _, l := range strings.Split(string(data), "\n") {
		if owned[directiveKey(l)] {
			continue
		}
		outLines = append(outLines, l)
	}
	outLines = append(outLines, hookLines...)
	outLines = append(outLines, HookEnvDirectives()...)
	outLines = append(outLines, runtimeLines...)
	outLines = append(outLines, toAdd...)
	if err := fsx.WriteFileAtomic(fsx.ServerConf(), []byte(strings.Join(outLines, "\n")+"\n"), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func EnsureClientTemplate() error {
	template := filepath.Join(fsx.OpenVPNRoot(), "server", "client-common.txt")
	if info, err := os.Lstat(template); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular client template at %s", template)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(template), 0o755); err != nil {
		return err
	}
	proto := FreshProto()
	port := OpenVPNPort()
	tunnelAddr := Env("TUNNEL_ADDRESS", "")
	if tunnelAddr == "" {
		// Fallback: try to read from config
		data, err := os.ReadFile(fsx.ServerConf())
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "remote ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					tunnelAddr = parts[1]
					break
				}
			}
		}
	}
	if tunnelAddr == "" {
		tunnelAddr = "auto"
	}

	tmpl := "client\ndev tun\nproto " + proto + "\n" + RemoteLines(tunnelAddr, port) + "\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\ntls-version-min 1.3\nauth SHA256\ndata-ciphers AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305\ncipher AES-128-GCM\nignore-unknown-option block-outside-dns\nblock-outside-dns\nmssfix 1360\nverb 3\n"
	return fsx.WriteFileAtomic(template, []byte(tmpl), 0o644)
}

func itoaStr(n int) string {
	return fmt.Sprintf("%d", n)
}

// HookEnvDirectives exports non-secret effective hook settings via OpenVPN
// setenv directives, so the dropped-UID hooks receive them as environment
// variables without reading the private .env.
func HookEnvDirectives() []string {
	cfg := config.HookFromEnv()
	settings := [][2]string{
		{"OVNODE_OPENVPN_ROOT", cfg.OpenVPNRoot}, {"OVNODE_DATA_DIR", fsx.OVNodeDir()},
		{"OVNODE_USERS_DIR", cfg.UsersDir}, {"OVNODE_SESSIONS_DIR", cfg.SessionsDir}, {"OVNODE_USAGE_DIR", cfg.UsageDir},
		{"OVNODE_STATUS_FILE", cfg.StatusFile}, {"OVNODE_LOG_DIR", cfg.LogDir}, {"OVNODE_LOG_FILE", cfg.LogFile},
		{"OVNODE_MANAGEMENT_HOST", cfg.MgmtHost}, {"OVNODE_MANAGEMENT_PORT", itoaStr(cfg.MgmtPort)}, {"OVNODE_MGMT_PASS_FILE", cfg.MgmtPassFile},
		{"OVNODE_ALLOW_REMOTE_MGMT", fsx.Env("ALLOW_REMOTE_MGMT", "0")},
		{"OVNODE_RUNTIME_USER", RuntimeUser()}, {"OVNODE_RUNTIME_GROUP", RuntimeGroup()}, {"OVNODE_SESSION_TTL", itoaStr(cfg.SessionTTL)},
	}
	out := make([]string, 0, len(settings))
	for _, setting := range settings {
		out = append(out, "setenv "+setting[0]+" "+configValue(setting[1]))
	}
	return out
}

func configValue(value string) string {
	if strings.ContainsAny(value, " \t\r\n\"\\") {
		return strconv.Quote(value)
	}
	return value
}

func hooksAlreadyCurrent(data string, desired []string) bool {
	counts := map[string]int{}
	values := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		key := directiveKey(line)
		counts[key]++
		values[key] = strings.TrimSpace(line)
	}
	for _, d := range desired {
		key := directiveKey(d)
		if counts[key] != 1 || values[key] != d {
			return false
		}
	}
	return true
}

func directiveKey(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	if fields[0] == "setenv" && len(fields) > 1 {
		return "setenv " + strings.Trim(fields[1], `"'`)
	}
	return fields[0]
}
