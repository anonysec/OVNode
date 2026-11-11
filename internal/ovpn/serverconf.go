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

func FreshProto() string {
	return currentSettings().Protos()[0]
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

func FreshServerConf(proto string) string {
	if EnsureMgmtPassword() == "" {
		return ""
	}
	cfg := currentSettings()
	port := cfg.Port
	dnsServers := policy.DNSEffective(cfg.DNSPrimary, cfg.DNSSecondary)
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

	enabled, prefix := ipv6Effective()
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
	confPath := fsx.ServerConf(proto)
	if _, err := os.Lstat(confPath); os.IsNotExist(err) {
		data := FreshServerConf(proto)
		if data == "" {
			return false, fmt.Errorf("server configuration could not be generated")
		}
		if err := os.MkdirAll(fsx.ServerDir(proto), 0o750); err != nil {
			return false, err
		}
		if err := fsx.WriteFileAtomic(confPath, []byte(data), 0o644); err != nil {
			return false, err
		}
		return true, nil
	} else if err != nil {
		return false, err
	}
	data, err := os.ReadFile(confPath)
	if err != nil {
		return false, err
	}

	// The agent owns these directives outright: their values come from the
	// instance and the protocol (paths, ports, runtime user), so a stale line
	// is replaced, not appended to. This is what keeps a port change from
	// leaving a second management or setenv line behind.
	ht := HookTargets()
	managed := append([]string{}, HardeningDirectives(proto)...)
	managed = append(managed, "tls-version-min "+currentSettings().TLSMin)
	managed = append(managed,
		"duplicate-cn",
		"crl-verify "+fsx.CRLFile(),
		"status "+configValue(fsx.StatusFile(proto))+" 5",
	)
	managed = append(managed,
		"client-connect \""+ht["client-connect"]+"\"",
		"client-disconnect \""+ht["client-disconnect"]+"\"",
	)
	managed = append(managed, HookEnvDirectives(proto)...)
	managed = append(managed, "user "+RuntimeUser(), "group "+RuntimeGroup())

	if managedCurrent(string(data), managed) {
		return false, nil
	}
	owned := make(map[string]bool, len(managed))
	for _, line := range managed {
		owned[directiveKey(line)] = true
	}
	out := make([]string, 0, len(managed)+16)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" || owned[directiveKey(line)] {
			continue
		}
		out = append(out, line)
	}
	out = append(out, managed...)
	if err := fsx.WriteFileAtomic(confPath, []byte(strings.Join(out, "\n")+"\n"), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// managedCurrent reports whether every managed directive appears exactly once
// with the desired value. A duplicate counts as drift, so the rewrite collapses
// it instead of appending another copy.
func managedCurrent(data string, managed []string) bool {
	counts := map[string]int{}
	values := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		key := directiveKey(line)
		if key == "" {
			continue
		}
		counts[key]++
		values[key] = strings.TrimSpace(line)
	}
	for _, want := range managed {
		key := directiveKey(want)
		if counts[key] != 1 || values[key] != want {
			return false
		}
	}
	return true
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
	port := cfg.Port
	tunnelAddr := Get("TunnelAddress", "")
	if tunnelAddr == "" {
		tunnelAddr = "auto"
	}

	var blocks strings.Builder
	for _, proto := range cfg.Protos() {
		blocks.WriteString("<connection>\n")
		blocks.WriteString("remote " + tunnelAddr + " " + itoaStr(port) + " " + proto + "\n")
		blocks.WriteString("</connection>\n")
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
