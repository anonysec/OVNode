// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"ovnode/internal/config"
	"ovnode/internal/fsx"
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

// MgmtLine returns one protocol's management directive.
func MgmtLine(proto string) string {
	return fmt.Sprintf("management 127.0.0.1 %d %s", ManagementPort(proto), configValue(fsx.MgmtPassFile()))
}

func HardeningDirectives(proto string) []string {
	EnsureMgmtPassword()
	return []string{
		"remote-cert-tls client",
		MgmtLine(proto),
		"writepid " + fsx.PIDFile(proto),
		"script-security 2",
		"status-version 3",
	}
}

func FreshServerConf(proto string) string {
	if EnsureMgmtPassword() == "" {
		return ""
	}
	cfg := currentSettings()
	port := cfg.Port
	dnsServers := []string{}
	if cfg.DNSPrimary != "" {
		dnsServers = append(dnsServers, cfg.DNSPrimary)
	}
	if cfg.DNSSecondary != "" {
		dnsServers = append(dnsServers, cfg.DNSSecondary)
	}
	user := RuntimeUser()
	group := RuntimeGroup()
	ht := HookTargets()

	var lines []string
	lines = append(lines, "port "+itoaStr(port))
	lines = append(lines, "proto "+proto)
	lines = append(lines, "dev tun")
	lines = append(lines, "topology subnet")
	lines = append(lines, "server "+VPNNetworkFor(proto)+" "+VPNNetmask())
	lines = append(lines, fmt.Sprintf("ifconfig-pool-persist %s 600", filepath.Join(fsx.ServerDir(proto), "ipp.txt")))
	if cfg.RedirectGateway {
		lines = append(lines, `push "redirect-gateway def1 bypass-dhcp"`)
	}
	for _, dns := range dnsServers {
		lines = append(lines, fmt.Sprintf(`push "dhcp-option DNS %s"`, dns))
	}
	if cfg.DNSDomain != "" {
		lines = append(lines, fmt.Sprintf(`push "dhcp-option DOMAIN %s"`, cfg.DNSDomain))
	}
	if cfg.BlockOutsideDNS {
		lines = append(lines, `push "block-outside-dns"`)
	}
	for _, route := range cfg.PushRoutes {
		lines = append(lines, fmt.Sprintf(`push "route %s"`, route))
	}

	enabled, prefix := cfg.IPv6Enabled, cfg.IPv6Prefix
	if enabled {
		lines = append(lines, "tun-ipv6")
		lines = append(lines, "server-ipv6 "+prefix)
		lines = append(lines, `push "route-ipv6 2000::/3"`)
	}
	if cfg.TunMTU != 0 {
		lines = append(lines, "tun-mtu "+itoaStr(cfg.TunMTU))
	}
	if cfg.Mssfix != 0 {
		lines = append(lines, "mssfix "+itoaStr(cfg.Mssfix))
	}
	lines = append(lines, "keepalive "+itoaStr(cfg.KeepalivePing)+" "+itoaStr(cfg.KeepaliveTimeout))
	lines = append(lines, "ca "+fsx.CACert())
	lines = append(lines, "cert "+fsx.ServerCert())
	lines = append(lines, "key "+filepath.Join(fsx.PKIDir(), "private", "server.key"))
	lines = append(lines, "dh none")
	lines = append(lines, "tls-crypt "+fsx.TLSKey())
	lines = append(lines, "tls-version-min "+cfg.TLSMin)
	lines = append(lines, "remote-cert-tls client")
	lines = append(lines, "data-ciphers "+upperCiphers(cfg.DataCiphers()))
	lines = append(lines, "data-ciphers-fallback "+upperCiphers(cfg.CipherFirst))
	lines = append(lines, "auth SHA256")
	lines = append(lines, "allow-compression no")
	lines = append(lines, "user "+user)
	lines = append(lines, "group "+group)
	// Export non-secret effective hook settings to the dropped-UID hooks via
	// OpenVPN setenv directives, so they do not need to read the private .env.
	lines = append(lines, HookEnvDirectives(proto)...)
	lines = append(lines, "persist-key")
	lines = append(lines, "persist-tun")
	// Quote the hook path because it contains a space ("ovnode hook connect")
	lines = append(lines, "client-connect \""+ht["client-connect"]+"\"")
	lines = append(lines, "client-disconnect \""+ht["client-disconnect"]+"\"")
	lines = append(lines, "client-config-dir "+filepath.Join(fsx.OpenVPNRoot(), "ccd"))
	lines = append(lines, "crl-verify "+fsx.CRLFile())
	lines = append(lines, "status "+configValue(fsx.StatusFile(proto))+" 5")
	lines = append(lines, "log-append "+fsx.OpenVPNLog(proto))
	lines = append(lines, "cd "+fsx.ServerDir(proto))

	lines = append(lines, HardeningDirectives(proto)...)

	if cfg.ClientToClient {
		lines = append(lines, "client-to-client")
	}
	if cfg.RenegSec > 0 {
		lines = append(lines, "reneg-sec "+itoaStr(cfg.RenegSec))
	}
	if cfg.InactiveTimeout > 0 {
		lines = append(lines, "inactive "+itoaStr(cfg.InactiveTimeout))
	}
	lines = append(lines, "verb "+itoaStr(cfg.Verb))
	lines = append(lines, "max-clients "+itoaStr(cfg.MaxClients))
	lines = append(lines, "explicit-exit-notify "+map[bool]string{true: "1", false: "0"}[proto == "udp"])
	lines = append(lines, "duplicate-cn")

	return strings.Join(lines, "\n") + "\n"
}

// upperCiphers maps our lower-case cipher names to OpenVPN's upper-case
// spellings for server.conf.
func upperCiphers(list string) string {
	parts := strings.Split(list, ":")
	for i, p := range parts {
		switch p {
		case "aes-128-gcm":
			parts[i] = "AES-128-GCM"
		case "aes-256-gcm":
			parts[i] = "AES-256-GCM"
		case "chacha20-poly1305":
			parts[i] = "CHACHA20-POLY1305"
		}
	}
	return strings.Join(parts, ":")
}

// EnsureServerConf regenerates the configuration for every selected protocol
// and removes a stale configuration for a protocol that is no longer in use.
func EnsureServerConf() bool {
	changed := false
	protos := currentSettings().Protos()
	for _, proto := range protos {
		if c, _ := ensureServerConf(proto); c {
			changed = true
		}
	}
	for _, proto := range []string{"udp", "tcp"} {
		if !slices.Contains(protos, proto) {
			if err := os.Remove(fsx.ServerConf(proto)); err == nil {
				changed = true
			}
		}
	}
	return changed
}

func ensureServerConf(proto string) (bool, error) {
	if EnsureMgmtPassword() == "" {
		return false, fmt.Errorf("management password unavailable at %s", fsx.MgmtPassFile())
	}
	want := FreshServerConf(proto)
	if want == "" {
		return false, fmt.Errorf("server configuration could not be generated")
	}
	path := fsx.ServerConf(proto)
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	merged := mergeConf(want, string(old))
	if string(old) == merged {
		return false, nil
	}
	if err := os.MkdirAll(fsx.ServerDir(proto), 0o750); err != nil {
		return false, err
	}
	if err := fsx.WriteFileAtomic(path, []byte(merged), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// mergeConf renders the settings-owned configuration and keeps directives it
// does not know about, so an operator's extra `push`/`route` line survives a
// settings change. Owned directives always come from settings.
func mergeConf(fresh, old string) string {
	owned := map[string]bool{}
	for _, line := range strings.Split(fresh, "\n") {
		if key := directiveKey(line); key != "" {
			owned[key] = true
		}
	}
	out := strings.Split(strings.TrimRight(fresh, "\n"), "\n")
	for _, line := range strings.Split(old, "\n") {
		key := directiveKey(line)
		if key == "" || owned[key] {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n") + "\n"
}

// directiveKey names the slot a directive occupies: the whole `setenv KEY`
// pair for setenv lines (the value is the payload, not the slot), the first
// word otherwise. Values are compared separately.
// EnsureClientTemplate writes the shared client template. Every profile uses
// <connection> blocks: one for a single-protocol node, two for "both", so the
// same profile works whether UDP or TCP is reachable. The panel substitutes
// the real address for "auto" at download time.
func EnsureClientTemplate() error {
	template := fsx.ClientTemplate()
	if info, err := os.Lstat(template); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("non-regular client template at %s", template)
	}
	cfg := currentSettings()
	tunnelAddr := cfg.TunnelAddress
	if tunnelAddr == "" {
		tunnelAddr = "auto"
	}
	ports := append([]int{cfg.Port}, cfg.ExtraPorts...)

	var blocks strings.Builder
	for _, proto := range cfg.Protos() {
		for _, port := range ports {
			blocks.WriteString("<connection>\n")
			blocks.WriteString("remote " + tunnelAddr + " " + itoaStr(port) + " " + proto + "\n")
			blocks.WriteString("</connection>\n")
		}
	}
	tmpl := "client\ndev tun\n" + blocks.String() +
		"resolv-retry infinite\nnobind\npersist-key\npersist-tun\n" +
		"remote-cert-tls server\ntls-version-min " + cfg.TLSMin + "\n" +
		"auth SHA256\ndata-ciphers " + upperCiphers(cfg.DataCiphers()) + "\n" +
		"cipher " + upperCiphers(cfg.CipherFirst) + "\n" +
		"ignore-unknown-option block-outside-dns\nblock-outside-dns\nverb 3\n"

	if current, err := os.ReadFile(template); err == nil && string(current) == tmpl {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(template), 0o755); err != nil {
		return err
	}
	return fsx.WriteFileAtomic(template, []byte(tmpl), 0o644)
}

func itoaStr(n int) string {
	return fmt.Sprintf("%d", n)
}

// HookEnvDirectives exports non-secret effective hook settings via OpenVPN
// setenv directives, so the dropped-UID hooks receive them as environment
// variables without reading the private .env.
func HookEnvDirectives(proto string) []string {
	cfg := config.HookFromEnv()
	settings := [][2]string{
		{"OpenVpnRoot", cfg.OpenVPNRoot}, {"DataDir", fsx.OVNodeDir()},
		{"UsersDir", cfg.UsersDir}, {"SessionsDir", cfg.SessionsDir}, {"UsageDir", cfg.UsageDir},
		{"StatusFile", fsx.StatusFile(proto)}, {"LogDir", cfg.LogDir}, {"LogFile", cfg.LogFile},
		{"ManagementHost", cfg.MgmtHost}, {"ManagementPort", itoaStr(ManagementPort(proto))}, {"MgmtPassFile", cfg.MgmtPassFile},
		{"AllowRemoteMgmt", fsx.Get("AllowRemoteMgmt", "0")},
		{"RuntimeUser", RuntimeUser()}, {"RuntimeGroup", RuntimeGroup()}, {"SessionTtlSeconds", itoaStr(cfg.SessionTTL)},
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
