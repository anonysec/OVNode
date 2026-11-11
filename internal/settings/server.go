// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package settings is the node's OpenVPN configuration model.
//
// It is the single source of truth for everything the panel can tune: one
// JSON file, typed fields, validated on the way in and out. Environment
// variables only seed the defaults on a fresh install; after that the file
// wins, so a panel change and an operator edit cannot disagree.
package settings

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"ovnode/internal/fsx"
)

// Protocol values accepted by the panel and the installer.
const (
	ProtoUDP  = "udp"
	ProtoTCP  = "tcp"
	ProtoBoth = "both"
)

// Cipher suites in preference order.
const (
	CipherAES128 = "aes-128-gcm"
	CipherAES256 = "aes-256-gcm"
	CipherChaCha = "chacha20-poly1305"
)

// Server is the tunable OpenVPN server configuration.
type Server struct {
	Protocol string `json:"Protocol"`
	Port     int    `json:"Port"`
	// TunnelAddress is the address clients dial; "auto" is replaced by the
	// panel at download time.
	TunnelAddress string `json:"TunnelAddress"`
	// ExtraPorts are additional listeners advertised in client profiles.
	ExtraPorts []int `json:"ExtraPorts"`

	MaxClients       int  `json:"MaxClients"`
	KeepalivePing    int  `json:"KeepalivePing"`
	KeepaliveTimeout int  `json:"KeepaliveTimeout"`
	ExplicitExit     bool `json:"ExplicitExitNotify"`

	RedirectGateway bool     `json:"RedirectGateway"`
	BlockOutsideDNS bool     `json:"BlockOutsideDns"`
	ClientToClient  bool     `json:"ClientToClient"`
	DNSPrimary      string   `json:"DnsPrimary"`
	DNSSecondary    string   `json:"DnsSecondary"`
	DNSDomain       string   `json:"DnsDomain"`
	PushRoutes      []string `json:"PushRoutes"`

	IPv6Enabled bool   `json:"Ipv6Enabled"`
	IPv6Prefix  string `json:"Ipv6Prefix"`

	// 0 means "let OpenVPN/the OS decide".
	TunMTU int `json:"TunMtu"`
	Mssfix int `json:"Mssfix"`

	CipherFirst string `json:"CipherFirst"`
	TLSMin      string `json:"TlsMin"`
	RenegSec    int    `json:"RenegSec"`
	// 0 disables the idle client killer.
	InactiveTimeout int `json:"InactiveTimeout"`
	Verb            int `json:"Verb"`
}

// Path is the settings file for this instance.
func Path() string {
	return filepath.Join(fsx.OVNodeDir(), "state", "openvpn.json")
}

// Defaults returns the shipped configuration. It reads nothing: the
// installer seeds the file from the install flags, and after that the file is
// the only source. A missing file therefore means "factory defaults", not
// "whatever the environment happens to say".
func Defaults() Server {
	return Server{
		Protocol:         ProtoUDP,
		Port:             1194,
		TunnelAddress:    "auto",
		ExtraPorts:       nil,
		MaxClients:       250,
		KeepalivePing:    10,
		KeepaliveTimeout: 60,
		ExplicitExit:     true,
		RedirectGateway:  true,
		BlockOutsideDNS:  true,
		ClientToClient:   false,
		DNSPrimary:       "1.1.1.1",
		DNSSecondary:     "8.8.8.8",
		DNSDomain:        "",
		PushRoutes:       nil,
		IPv6Enabled:      false,
		IPv6Prefix:       "fd42:42:42:42::/64",
		TunMTU:           0,
		Mssfix:           0,
		CipherFirst:      CipherAES128,
		TLSMin:           "1.3",
		RenegSec:         3600,
		InactiveTimeout:  0,
		Verb:             3,
	}
}

// NormalizeProtocol accepts the spellings the panel and installers use.
func NormalizeProtocol(p string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", ProtoUDP, "udp4", "udp6":
		return ProtoUDP, true
	case ProtoTCP, "tcp4", "tcp6":
		return ProtoTCP, true
	case ProtoBoth:
		return ProtoBoth, true
	}
	return "", false
}

// Protos expands a protocol choice into the processes to run.
func (s Server) Protos() []string {
	switch s.Protocol {
	case ProtoBoth:
		return []string{ProtoUDP, ProtoTCP}
	case ProtoTCP:
		return []string{ProtoTCP}
	default:
		return []string{ProtoUDP}
	}
}

// Load reads the instance's settings file.
func Load() (Server, error) { return LoadFrom(Path()) }

// LoadFrom reads settings from path. A missing file returns Defaults; a
// corrupt file is an error, never a silent reset.
func LoadFrom(path string) (Server, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Defaults(), nil
	}
	if err != nil {
		return Server{}, err
	}
	var s Server
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Server{}, fmt.Errorf("read %s: %w", path, err)
	}
	if dec.More() {
		return Server{}, fmt.Errorf("read %s: trailing data", path)
	}
	if err := s.Validate(); err != nil {
		return Server{}, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Save writes the instance's settings file.
func Save(s Server) error { return SaveTo(Path(), s) }

// SaveTo validates and writes settings to path atomically with 0600.
func SaveTo(path string, s Server) error {
	if err := s.Validate(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if err := fsx.WriteFileAtomic(path, body, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// Validate checks every field against the bounds the UI enforces.
func (s Server) Validate() error {
	if _, ok := NormalizeProtocol(s.Protocol); !ok {
		return fmt.Errorf("protocol %q is not udp, tcp or both", s.Protocol)
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("port %d is outside 1-65535", s.Port)
	}
	if s.TunnelAddress != "" && s.TunnelAddress != "auto" {
		if net.ParseIP(s.TunnelAddress) == nil && !validDomain(s.TunnelAddress) {
			return fmt.Errorf("tunnelAddress %q is not an IP or hostname", s.TunnelAddress)
		}
	}
	seen := map[int]bool{s.Port: true}
	for _, p := range s.ExtraPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("extra port %d is outside 1-65535", p)
		}
		if seen[p] {
			return fmt.Errorf("extra port %d is listed twice", p)
		}
		seen[p] = true
	}
	if s.MaxClients < 1 || s.MaxClients > 10000 {
		return fmt.Errorf("maxClients %d is outside 1-10000", s.MaxClients)
	}
	if s.KeepalivePing < 5 || s.KeepalivePing > 300 {
		return fmt.Errorf("keepalivePing %d is outside 5-300", s.KeepalivePing)
	}
	if s.KeepaliveTimeout < 30 || s.KeepaliveTimeout > 900 {
		return fmt.Errorf("keepaliveTimeout %d is outside 30-900", s.KeepaliveTimeout)
	}
	if s.KeepaliveTimeout <= s.KeepalivePing {
		return fmt.Errorf("keepaliveTimeout must be greater than KeepalivePing")
	}
	for name, addr := range map[string]string{"DnsPrimary": s.DNSPrimary, "DnsSecondary": s.DNSSecondary} {
		if addr != "" && net.ParseIP(addr) == nil {
			return fmt.Errorf("%s %q is not an IP address", name, addr)
		}
	}
	if s.DNSDomain != "" && !validDomain(s.DNSDomain) {
		return fmt.Errorf("dnsDomain %q is not a valid domain", s.DNSDomain)
	}
	for _, route := range s.PushRoutes {
		if _, _, err := net.ParseCIDR(route); err != nil {
			return fmt.Errorf("pushRoutes entry %q is not a CIDR", route)
		}
	}
	if s.IPv6Enabled {
		ip, _, err := net.ParseCIDR(s.IPv6Prefix)
		if err != nil || ip.To4() != nil {
			return fmt.Errorf("ipv6Prefix %q is not an IPv6 CIDR", s.IPv6Prefix)
		}
	}
	if s.TunMTU != 0 && (s.TunMTU < 1200 || s.TunMTU > 1500) {
		return fmt.Errorf("tunMtu %d is outside 1200-1500 (0 = auto)", s.TunMTU)
	}
	if s.Mssfix != 0 && (s.Mssfix < 500 || s.Mssfix > 1450) {
		return fmt.Errorf("mssfix %d is outside 500-1450 (0 = auto)", s.Mssfix)
	}
	switch s.CipherFirst {
	case CipherAES128, CipherAES256, CipherChaCha:
	default:
		return fmt.Errorf("cipherFirst %q is not a supported cipher", s.CipherFirst)
	}
	switch s.TLSMin {
	case "1.2", "1.3":
	default:
		return fmt.Errorf("tlsMin %q is not 1.2 or 1.3", s.TLSMin)
	}
	if s.RenegSec < 600 || s.RenegSec > 86400 {
		return fmt.Errorf("renegSec %d is outside 600-86400", s.RenegSec)
	}
	if s.InactiveTimeout < 0 || s.InactiveTimeout > 86400 {
		return fmt.Errorf("inactiveTimeout %d is outside 0-86400", s.InactiveTimeout)
	}
	if s.Verb < 0 || s.Verb > 4 {
		return fmt.Errorf("verb %d is outside 0-4", s.Verb)
	}
	return nil
}

// DataCiphers is the OpenVPN data-ciphers list with the chosen suite first.
func (s Server) DataCiphers() string {
	all := []string{CipherAES128, CipherAES256, CipherChaCha}
	first := s.CipherFirst
	if first == "" {
		first = CipherAES128
	}
	out := []string{first}
	for _, c := range all {
		if c != first {
			out = append(out, c)
		}
	}
	return strings.Join(out, ":")
}

func validDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, r := range label {
			if (i == 0 || i == len(label)-1) && r == '-' {
				return false
			}
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
