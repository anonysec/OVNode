// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"ovnode/internal/fsx"
	"ovnode/internal/logging"
	"ovnode/internal/policy"
	"ovnode/internal/settings"
)

var changeConfigMu sync.Mutex

// ChangeConfigRequest mirrors the panel's pushed settings.
type ChangeConfigRequest struct {
	Settings      *SettingsPatch `json:"settings"`
	OVPNPort      any            `json:"ovpn_port"`
	Protocol      string         `json:"protocol"`
	TunnelAddress string         `json:"tunnel_address"`
	SetNewSetting *bool          `json:"set_new_setting"`
	DNS1          *string        `json:"dns1"`
	DNS2          *string        `json:"dns2"`
	EnableIPv6    *bool          `json:"enable_ipv6"`
	IPv6Prefix    *string        `json:"ipv6_prefix"`
	ExtraPorts    any            `json:"extra_ports"`
}

// SettingsPatch carries a partial settings update from the panel. Every field
// is optional; omitted fields keep their current value.
type SettingsPatch struct {
	Protocol         *string   `json:"Protocol"`
	Port             *int      `json:"Port"`
	TunnelAddress    *string   `json:"TunnelAddress"`
	ExtraPorts       *[]int    `json:"ExtraPorts"`
	MaxClients       *int      `json:"MaxClients"`
	KeepalivePing    *int      `json:"KeepalivePing"`
	KeepaliveTimeout *int      `json:"KeepaliveTimeout"`
	ExplicitExit     *bool     `json:"ExplicitExitNotify"`
	RedirectGateway  *bool     `json:"RedirectGateway"`
	BlockOutsideDNS  *bool     `json:"BlockOutsideDns"`
	ClientToClient   *bool     `json:"ClientToClient"`
	DNSPrimary       *string   `json:"DnsPrimary"`
	DNSSecondary     *string   `json:"DnsSecondary"`
	DNSDomain        *string   `json:"DnsDomain"`
	PushRoutes       *[]string `json:"PushRoutes"`
	IPv6Enabled      *bool     `json:"Ipv6Enabled"`
	IPv6Prefix       *string   `json:"Ipv6Prefix"`
	TunMTU           *int      `json:"TunMtu"`
	Mssfix           *int      `json:"Mssfix"`
	CipherFirst      *string   `json:"CipherFirst"`
	TLSMin           *string   `json:"TlsMin"`
	RenegSec         *int      `json:"RenegSec"`
	InactiveTimeout  *int      `json:"InactiveTimeout"`
	Verb             *int      `json:"Verb"`
}

// ChangeConfigResult classifies how the change was applied.
type ChangeConfigResult struct {
	RestartRequired bool
	HotReload       bool
}

// cfgChange is the validated form of a ChangeConfigRequest. Optional fields
// carry the current value when the request did not mention them, so applying
// the struct is a full replacement rather than a partial patch.
type cfgChange struct {
	ovpnPort      int
	proto         string
	tunnelAddr    string
	dnsProvided   bool
	dns1          string
	dns2          string
	ipv6Provided  bool
	enableIPv6    bool
	ipv6Prefix    string
	extraProvided bool
	extraPorts    []int
}

var tunnelRe = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

// ReadConfig returns the effective settings the panel displays.
func ReadConfig() map[string]any {
	cfg, err := settings.Load()
	if err != nil {
		logging.Warn("read settings: %v", err)
		cfg = settings.Defaults()
	}
	return map[string]any{
		"settings":       cfg,
		"port":           cfg.Port,
		"proto":          cfg.Protocol,
		"tunnel_address": cfg.TunnelAddress,
		"dns1":           cfg.DNSPrimary,
		"dns2":           cfg.DNSSecondary,
		"enable_ipv6":    cfg.IPv6Enabled,
		"ipv6_prefix":    cfg.IPv6Prefix,
		"extra_ports":    cfg.ExtraPorts,
	}
}

// ChangeConfig validates and applies a panel push to the settings file.
func ChangeConfig(req ChangeConfigRequest) (ChangeConfigResult, error) {
	changeConfigMu.Lock()
	defer changeConfigMu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			logging.Syslog("ChangeConfig panic: %v", r)
		}
	}()
	if req.Settings != nil {
		return applySettingsPatch(*req.Settings)
	}
	c, err := parseConfigRequest(req)
	if err != nil {
		return ChangeConfigResult{}, err
	}
	return applyConfigChange(c)
}

// applySettingsPatch merges a partial settings update, regenerates the
// configuration and restarts or reloads the children.
func applySettingsPatch(patch SettingsPatch) (ChangeConfigResult, error) {
	old, err := settings.Load()
	if err != nil {
		return ChangeConfigResult{}, fmt.Errorf("could not read node settings")
	}
	next := old
	if patch.Protocol != nil {
		proto, ok := settings.NormalizeProtocol(*patch.Protocol)
		if !ok {
			return ChangeConfigResult{}, fmt.Errorf("protocol must be tcp, udp or both")
		}
		next.Protocol = proto
	}
	if patch.Port != nil {
		next.Port = *patch.Port
	}
	if patch.TunnelAddress != nil {
		next.TunnelAddress = *patch.TunnelAddress
	}
	if patch.ExtraPorts != nil {
		next.ExtraPorts = *patch.ExtraPorts
	}
	if patch.MaxClients != nil {
		next.MaxClients = *patch.MaxClients
	}
	if patch.KeepalivePing != nil {
		next.KeepalivePing = *patch.KeepalivePing
	}
	if patch.KeepaliveTimeout != nil {
		next.KeepaliveTimeout = *patch.KeepaliveTimeout
	}
	if patch.ExplicitExit != nil {
		next.ExplicitExit = *patch.ExplicitExit
	}
	if patch.RedirectGateway != nil {
		next.RedirectGateway = *patch.RedirectGateway
	}
	if patch.BlockOutsideDNS != nil {
		next.BlockOutsideDNS = *patch.BlockOutsideDNS
	}
	if patch.ClientToClient != nil {
		next.ClientToClient = *patch.ClientToClient
	}
	if patch.DNSPrimary != nil {
		next.DNSPrimary = *patch.DNSPrimary
	}
	if patch.DNSSecondary != nil {
		next.DNSSecondary = *patch.DNSSecondary
	}
	if patch.DNSDomain != nil {
		next.DNSDomain = *patch.DNSDomain
	}
	if patch.PushRoutes != nil {
		next.PushRoutes = *patch.PushRoutes
	}
	if patch.IPv6Enabled != nil {
		next.IPv6Enabled = *patch.IPv6Enabled
	}
	if patch.IPv6Prefix != nil {
		next.IPv6Prefix = *patch.IPv6Prefix
	}
	if patch.TunMTU != nil {
		next.TunMTU = *patch.TunMTU
	}
	if patch.Mssfix != nil {
		next.Mssfix = *patch.Mssfix
	}
	if patch.CipherFirst != nil {
		next.CipherFirst = *patch.CipherFirst
	}
	if patch.TLSMin != nil {
		next.TLSMin = *patch.TLSMin
	}
	if patch.RenegSec != nil {
		next.RenegSec = *patch.RenegSec
	}
	if patch.InactiveTimeout != nil {
		next.InactiveTimeout = *patch.InactiveTimeout
	}
	if patch.Verb != nil {
		next.Verb = *patch.Verb
	}
	if reflect.DeepEqual(next, old) {
		return ChangeConfigResult{}, nil
	}
	if err := settings.Save(next); err != nil {
		return ChangeConfigResult{}, err
	}
	rollback := func() {
		_ = settings.Save(old)
		EnsureServerConf()
		_ = EnsureClientTemplate()
		invalidateCachedOVPN()
	}
	EnsureServerConf()
	if err := EnsureClientTemplate(); err != nil {
		rollback()
		return ChangeConfigResult{}, fmt.Errorf("client template: %w", err)
	}
	invalidateCachedOVPN()

	restart := next.Protocol != old.Protocol ||
		next.Port != old.Port ||
		next.IPv6Enabled != old.IPv6Enabled ||
		next.IPv6Prefix != old.IPv6Prefix
	if restart {
		if OpenVPNIsRunning() && !RestartOpenVPN() {
			rollback()
			return ChangeConfigResult{RestartRequired: true}, fmt.Errorf("OpenVPN restart failed")
		}
		return ChangeConfigResult{RestartRequired: true}, nil
	}
	if OpenVPNIsRunning() && !ReloadOpenVPN() {
		rollback()
		return ChangeConfigResult{}, fmt.Errorf("OpenVPN reload failed")
	}
	return ChangeConfigResult{HotReload: true}, nil
}

// applyConfigChange writes the settings file, regenerates every protocol's
// configuration and template, and restarts or reloads the children. A failed
// restart rolls the file back and regenerates the previous configuration.
func applyConfigChange(c cfgChange) (ChangeConfigResult, error) {
	old, err := settings.Load()
	if err != nil {
		return ChangeConfigResult{}, fmt.Errorf("could not read node settings")
	}
	next := old
	next.Protocol = c.proto
	next.Port = c.ovpnPort
	if c.tunnelAddr != "" {
		next.TunnelAddress = c.tunnelAddr
	}
	if c.dnsProvided {
		next.DNSPrimary, next.DNSSecondary = c.dns1, c.dns2
	}
	if c.ipv6Provided {
		next.IPv6Enabled, next.IPv6Prefix = c.enableIPv6, c.ipv6Prefix
	}
	if c.extraProvided {
		next.ExtraPorts = c.extraPorts
	}
	if reflect.DeepEqual(next, old) {
		return ChangeConfigResult{}, nil
	}
	if err := settings.Save(next); err != nil {
		return ChangeConfigResult{}, err
	}
	rollback := func() {
		_ = settings.Save(old)
		EnsureServerConf()
		_ = EnsureClientTemplate()
		invalidateCachedOVPN()
	}
	if EnsureServerConf() {
		// configuration files were rewritten
	}
	if err := EnsureClientTemplate(); err != nil {
		rollback()
		return ChangeConfigResult{}, fmt.Errorf("client template: %w", err)
	}
	invalidateCachedOVPN()

	restart := next.Protocol != old.Protocol ||
		next.Port != old.Port ||
		next.IPv6Enabled != old.IPv6Enabled ||
		next.IPv6Prefix != old.IPv6Prefix

	if restart {
		if OpenVPNIsRunning() && !RestartOpenVPN() {
			rollback()
			return ChangeConfigResult{RestartRequired: true}, fmt.Errorf("OpenVPN restart failed")
		}
		return ChangeConfigResult{RestartRequired: true}, nil
	}
	if OpenVPNIsRunning() && !ReloadOpenVPN() {
		rollback()
		return ChangeConfigResult{}, fmt.Errorf("OpenVPN reload failed")
	}
	return ChangeConfigResult{HotReload: true}, nil
}

// parseConfigRequest validates the request without touching the disk.
func parseConfigRequest(req ChangeConfigRequest) (cfgChange, error) {
	c, err := parseCore(req)
	if err != nil {
		return c, err
	}
	if err := parseDNS(req, &c); err != nil {
		return c, err
	}
	if err := parseIPv6(req, &c); err != nil {
		return c, err
	}
	if err := parseExtras(req, &c); err != nil {
		return c, err
	}
	return c, nil
}

func parseCore(req ChangeConfigRequest) (cfgChange, error) {
	var c cfgChange
	var ovpnPort int
	switch v := req.OVPNPort.(type) {
	case int:
		ovpnPort = v
	case float64:
		ovpnPort = int(v)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return c, fmt.Errorf("ovpn_port is not a number")
		}
		ovpnPort = n
	default:
		return c, fmt.Errorf("ovpn_port is required")
	}
	if ovpnPort < 1 || ovpnPort > 65535 {
		return c, fmt.Errorf("ovpn_port out of range")
	}
	if policy.IsReservedPrimaryPort(ovpnPort) {
		return c, fmt.Errorf("ovpn_port is a reserved port")
	}
	c.ovpnPort = ovpnPort
	proto, ok := normalizeProto(req.Protocol)
	if !ok {
		return c, fmt.Errorf("protocol must be tcp, udp or both")
	}
	c.proto = proto
	c.tunnelAddr = strings.TrimSpace(req.TunnelAddress)
	if c.tunnelAddr != "" && !tunnelRe.MatchString(c.tunnelAddr) {
		return c, fmt.Errorf("tunnel_address is malformed")
	}
	return c, nil
}

func parseDNS(req ChangeConfigRequest, c *cfgChange) error {
	current, err := settings.Load()
	if err != nil {
		current = settings.Defaults()
	}
	c.dns1, c.dns2 = current.DNSPrimary, current.DNSSecondary
	c.dnsProvided = req.DNS1 != nil || req.DNS2 != nil
	if req.DNS1 != nil {
		v := policy.ValidateIP(*req.DNS1)
		if *req.DNS1 != "" && v == "" {
			return fmt.Errorf("dns is not a valid IP")
		}
		c.dns1 = v
	}
	if req.DNS2 != nil {
		v := policy.ValidateIP(*req.DNS2)
		if *req.DNS2 != "" && v == "" {
			return fmt.Errorf("dns is not a valid IP")
		}
		c.dns2 = v
	}
	return nil
}

func parseIPv6(req ChangeConfigRequest, c *cfgChange) error {
	current, err := settings.Load()
	if err != nil {
		current = settings.Defaults()
	}
	c.enableIPv6, c.ipv6Prefix = current.IPv6Enabled, current.IPv6Prefix
	c.ipv6Provided = req.EnableIPv6 != nil || req.IPv6Prefix != nil
	if req.EnableIPv6 != nil {
		c.enableIPv6 = *req.EnableIPv6
	}
	if req.IPv6Prefix == nil {
		return nil
	}
	v := policy.ValidatePrefix(*req.IPv6Prefix)
	if v == "" {
		return fmt.Errorf("ipv6_prefix is not a valid prefix")
	}
	c.ipv6Prefix = v
	return nil
}

func parseExtras(req ChangeConfigRequest, c *cfgChange) error {
	c.extraProvided = req.ExtraPorts != nil
	if !c.extraProvided {
		return nil
	}
	raw, ok := extraPortsRaw(req.ExtraPorts)
	if !ok {
		return fmt.Errorf("extra_ports is malformed")
	}
	vp, err := policy.ValidateExtraPorts(raw, c.ovpnPort)
	if err != nil {
		return err
	}
	c.extraPorts = vp
	return nil
}

func normalizeProto(p string) (string, bool) {
	return settings.NormalizeProtocol(p)
}

func extraPortsRaw(v any) (string, bool) {
	switch val := v.(type) {
	case string:
		return val, true
	case []any:
		parts := []string{}
		for _, e := range val {
			switch x := e.(type) {
			case float64:
				parts = append(parts, strconv.Itoa(int(x)))
			case int:
				parts = append(parts, strconv.Itoa(x))
			case string:
				parts = append(parts, strings.TrimSpace(x))
			default:
				return "", false
			}
		}
		return strings.Join(parts, ","), true
	case []float64:
		parts := []string{}
		for _, e := range val {
			parts = append(parts, strconv.Itoa(int(e)))
		}
		return strings.Join(parts, ","), true
	case []int:
		parts := []string{}
		for _, e := range val {
			parts = append(parts, strconv.Itoa(e))
		}
		return strings.Join(parts, ","), true
	case []string:
		return strings.Join(val, ","), true
	default:
		return "", false
	}
}

// invalidateCachedOVPN drops per-user profile caches so the next download is
// rendered from the new template.
func invalidateCachedOVPN() {
	matches, _ := filepath.Glob(filepath.Join(fsx.UsersDir(), "*", "client.ovpn"))
	for _, m := range matches {
		_ = os.Remove(m)
	}
}
