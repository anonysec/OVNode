// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ovnode/internal/fsx"
	"ovnode/internal/policy"
)

var ourHookNames = map[string]bool{
	"ovnode-client-connect.sh":    true,
	"ovnode-client-disconnect.sh": true,
	"ovnode":                      true,
}

// HookTargets maps the client-connect/client-disconnect directives to the
// node's own binary.
func HookTargets() map[string]string {
	bin := filepath.Join(fsx.ScriptsDir(), "ovnode")
	return map[string]string{
		"client-connect":    bin + " hook connect",
		"client-disconnect": bin + " hook disconnect",
	}
}

func IsOVNodeHook(path string) bool {
	base := filepath.Base(path)
	return ourHookNames[base]
}

func EnsureMgmtPassword() string {
	path := fsx.MgmtPassFile()
	if _, err := os.Stat(path); err == nil {
		os.Chmod(path, 0o600)
		data, _ := os.ReadFile(path)
		if strings.TrimSpace(string(data)) != "" {
			return path
		}
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	pw := randomHex(32)
	_ = fsx.WriteFileAtomic(path, []byte(pw+"\n"), 0o600)
	os.Chmod(path, 0o600)
	return path
}

func randomHex(n int) string {
	b := make([]byte, n)
	readRand(b)
	out := make([]byte, n*2)
	const hexd = "0123456789abcdef"
	for i := 0; i < n; i++ {
		out[i*2] = hexd[b[i]>>4]
		out[i*2+1] = hexd[b[i]&0x0f]
	}
	return string(out)
}

func readRand(b []byte) {
	importCryptoRand(b)
}

// MgmtLine returns the management directive.
func MgmtLine() string {
	port := ManagementPort()
	return fmt.Sprintf("management 127.0.0.1 %d %s", port, fsx.MgmtPassFile())
}

func HardeningDirectives() []string {
	EnsureMgmtPassword()
	return []string{
		"tls-version-min 1.2",
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
	EnsureMgmtPassword()
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
	lines = append(lines, "persist-key")
	lines = append(lines, "persist-tun")
	lines = append(lines, "script-security 2")
	// Quote the hook path because it contains a space ("ovnode hook connect")
	lines = append(lines, "client-connect \""+ht["client-connect"]+"\"")
	lines = append(lines, "client-disconnect \""+ht["client-disconnect"]+"\"")
	lines = append(lines, "client-config-dir "+filepath.Join(fsx.OpenVPNRoot(), "ccd"))
	lines = append(lines, "crl-verify "+fsx.CRLFile())
	lines = append(lines, "status "+filepath.Join(fsx.OpenVPNRoot(), "server", "status.log")+" 5")
	lines = append(lines, "status-version 3")
	lines = append(lines, MgmtLine())
	lines = append(lines, "writepid "+fsx.PIDFile())
	lines = append(lines, "log-append "+filepath.Join(fsx.OpenVPNRoot(), "server", "openvpn.log"))
	lines = append(lines, "cd "+filepath.Join(fsx.OpenVPNRoot(), "server"))

	for _, d := range HardeningDirectives() {
		lines = append(lines, d)
	}

	lines = append(lines, "max-clients "+itoaStr(MaxClients()))
	lines = append(lines, "explicit-exit-notify "+map[bool]string{true: "1", false: "0"}[proto == "udp"])
	lines = append(lines, "duplicate-cn")

	return strings.Join(lines, "\n") + "\n"
}

func dnsEffective(defaults [2]string) []string {
	return policy.DNSEffective(defaults[0], defaults[1])
}

func EnsureServerConf() bool {
	if _, err := os.Stat(fsx.ServerConf()); err != nil {
		data := FreshServerConf()
		if err := fsx.WriteFileAtomic(fsx.ServerConf(), []byte(data), 0o644); err != nil {
			return false
		}
		return true
	}
	data, err := os.ReadFile(fsx.ServerConf())
	if err != nil {
		return false
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
	for _, d := range []string{
		"client-connect \"" + ht["client-connect"] + "\"",
		"client-disconnect \"" + ht["client-disconnect"] + "\"",
		"duplicate-cn",
	} {
		if !existing[d] {
			toAdd = append(toAdd, d)
		}
	}
	crl := "crl-verify " + fsx.CRLFile()
	if !existing[crl] {
		toAdd = append(toAdd, crl)
	}
	if len(toAdd) == 0 {
		return false
	}
	outLines := strings.Split(string(data), "\n")
	outLines = append(outLines, toAdd...)
	if err := fsx.WriteFileAtomic(fsx.ServerConf(), []byte(strings.Join(outLines, "\n")+"\n"), 0o644); err != nil {
		return false
	}
	return true
}

func EnsureClientTemplate() {
	template := filepath.Join(fsx.OpenVPNRoot(), "server", "client-common.txt")
	if _, err := os.Stat(template); err == nil {
		return
	}
	os.MkdirAll(filepath.Dir(template), 0o755)
	proto := FreshProto()
	port := OpenVPNPort()
	tunnelAddr := Env("TUNNEL_ADDRESS", "")
	if tunnelAddr == "" {
		// Fallback: try to read from config
		data, _ := os.ReadFile(fsx.ServerConf())
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
	if err := fsx.WriteFileAtomic(template, []byte(tmpl), 0o644); err != nil {
		return
	}
}

func itoaStr(n int) string {
	return fmt.Sprintf("%d", n)
}

func importCryptoRand(b []byte) {
	_, _ = rand.Read(b)
}
