// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"ovnode/internal/fsx"
	"ovnode/internal/logging"
	"ovnode/internal/policy"
)

var changeConfigMu sync.Mutex

// ChangeConfigRequest mirrors the panel's pushed settings.
//
// The json tags are load-bearing: without them Go's case-insensitive
// matching leaves "ovpn_port" unbound, and the panel's config push is a
// no-op that reports success.
type ChangeConfigRequest struct {
	OVPNPort      any     `json:"ovpn_port"`
	Protocol      string  `json:"protocol"`
	TunnelAddress string  `json:"tunnel_address"`
	SetNewSetting *bool   `json:"set_new_setting"`
	DNS1          *string `json:"dns1"`
	DNS2          *string `json:"dns2"`
	EnableIPv6    *bool   `json:"enable_ipv6"`
	IPv6Prefix    *string `json:"ipv6_prefix"`
	ExtraPorts    any     `json:"extra_ports"`
}

// ChangeConfigResult classification.
type ChangeConfigResult struct {
	RestartRequired bool
	HotReload       bool
}

var tunnelRe = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

func ReadConfig() map[string]any {
	out := map[string]any{"port": nil, "proto": nil, "tunnel_address": nil}
	data, err := os.ReadFile(settingFile())
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			s := strings.TrimSpace(line)
			if strings.HasPrefix(s, "port ") && out["port"] == nil {
				fields := strings.Fields(s)
				if len(fields) >= 2 {
					if n, err := strconv.Atoi(fields[1]); err == nil {
						out["port"] = n
					}
				}
			} else if strings.HasPrefix(s, "proto ") && out["proto"] == nil {
				fields := strings.Fields(s)
				if len(fields) >= 2 {
					out["proto"] = fields[1]
				}
			}
			if out["port"] != nil && out["proto"] != nil {
				break
			}
		}
	}
	tdata, err := os.ReadFile(templateFile())
	if err == nil {
		for _, line := range strings.Split(string(tdata), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 3 && fields[0] == "remote" {
				out["tunnel_address"] = fields[1]
				break
			}
		}
	}
	return out
}

func ChangeConfig(req ChangeConfigRequest, classification *ChangeConfigResult) bool {
	changeConfigMu.Lock()
	defer changeConfigMu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			logging.Syslog("ChangeConfig panic: %v", r)
		}
	}()
	setting := settingFile()
	template := templateFile()
	data, err := os.ReadFile(setting)
	if err != nil {
		return false
	}
	config := string(data)

	// parse port
	proto := "tcp"
	if strings.HasPrefix(strings.ToLower(req.Protocol), "tcp") {
		proto = "tcp"
	} else if req.Protocol != "" {
		proto = "udp"
	}
	ovpnPort := 0
	switch v := req.OVPNPort.(type) {
	case int:
		ovpnPort = v
	case float64:
		ovpnPort = int(v)
	case string:
		n, _ := strconv.Atoi(v)
		ovpnPort = n
	}
	if ovpnPort < 1 || ovpnPort > 65535 {
		return false
	}

	// validate DNS
	dnsProvided := req.DNS1 != nil || req.DNS2 != nil
	var validDNS1, validDNS2 *string
	if req.DNS1 != nil {
		v := policy.ValidateIP(*req.DNS1)
		if v == "" && *req.DNS1 != "" {
			return false
		}
		vv := v
		validDNS1 = &vv
	}
	if req.DNS2 != nil {
		v := policy.ValidateIP(*req.DNS2)
		if v == "" && *req.DNS2 != "" {
			return false
		}
		vv := v
		validDNS2 = &vv
	}

	// ipv6
	ipv6Provided := req.EnableIPv6 != nil || req.IPv6Prefix != nil
	if req.IPv6Prefix != nil {
		// validate via policy? just accept
	}

	// extra ports
	extraProvided := req.ExtraPorts != nil

	// old proto/port
	oldProtoMatch := regexp.MustCompile(`(?m)^proto\s+(\S+)`).FindStringSubmatch(config)
	oldPortMatch := regexp.MustCompile(`(?m)^port\s+(\d+)`).FindStringSubmatch(config)
	oldProto := ""
	oldPort := ""
	if len(oldProtoMatch) > 1 {
		oldProto = oldProtoMatch[1]
	}
	if len(oldPortMatch) > 1 {
		oldPort = oldPortMatch[1]
	}
	changed := !strings.HasPrefix(oldProto, proto) || oldPort != strconv.Itoa(ovpnPort)

	newConfig := regexp.MustCompile(`(?m)^port\s+\d+`).ReplaceAllString(config, "port "+strconv.Itoa(ovpnPort))
	newConfig = regexp.MustCompile(`(?m)^proto\s+\S+`).ReplaceAllString(newConfig, "proto "+proto)
	newConfig = regexp.MustCompile(`(?m)^explicit-exit-notify\s+\d+`).ReplaceAllString(newConfig, "explicit-exit-notify "+map[bool]string{true: "1", false: "0"}[proto == "udp"])

	dnsChanged := false
	if dnsProvided {
		def1, def2 := VPNDNS()
		dnsDesired := policy.DNSEffective(def1, def2)
		if validDNS1 != nil {
			if *validDNS1 != "" {
				dnsDesired = []string{*validDNS1}
				if validDNS2 != nil && *validDNS2 != "" {
					dnsDesired = append(dnsDesired, *validDNS2)
				}
			}
		}
		newConfig = policy.RewritePushDNS(newConfig, dnsDesired)
		dnsChanged = true
	}

	ipv6Changed := false
	if ipv6Provided {
		curEn, curPref := policy.IPv6Effective(IPv6Enabled(), IPv6Prefix())
		desEn := curEn
		if req.EnableIPv6 != nil {
			desEn = *req.EnableIPv6
		}
		desPref := curPref
		if req.IPv6Prefix != nil {
			if v := policy.ValidatePrefix(*req.IPv6Prefix); v != "" {
				desPref = v
			}
		}
		// rewrite block: simple append if missing
		if desEn {
			if !strings.Contains(newConfig, "tun-ipv6") {
				newConfig += "\ntun-ipv6\nserver-ipv6 " + desPref + "\n"
			}
		}
		policy.WriteIPv6State(desEn, desPref)
		ipv6Changed = true
	}

	confChanged := newConfig != config

	// snapshot state files
	_ = policy.PortsStatePath()

	if confChanged {
		// Snapshot before overwriting. The rollback below restores from
		// these; previously they were never written, so a failed restart
		// left the broken config in place.
		if data, err := os.ReadFile(setting); err == nil {
			_ = os.WriteFile(setting+".bak", data, 0o644)
		}
		_ = fsx.WriteFileAtomic(setting, []byte(newConfig), 0o644)
	}
	if dnsProvided {
		def1, def2 := VPNDNS()
		d1, d2 := def1, def2
		if validDNS1 != nil {
			d1 = *validDNS1
		}
		if validDNS2 != nil {
			d2 = *validDNS2
		}
		policy.WriteDNSState(d1, d2)
	}
	if ipv6Provided {
		// already written
	}

	// template
	tmplData, _ := os.ReadFile(template)
	originalTmpl := string(tmplData)
	tunnelAddr := strings.TrimSpace(req.TunnelAddress)
	if tunnelAddr != "" && !tunnelRe.MatchString(tunnelAddr) {
		return false
	}
	if tunnelAddr == "" {
		// keep first remote
		for _, line := range strings.Split(originalTmpl, "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 3 && fields[0] == "remote" {
				tunnelAddr = fields[1]
				break
			}
		}
		if tunnelAddr == "" || tunnelAddr == "UPDATE_VIA_PANEL" {
			tunnelAddr = NodePublicIP()
		}
	}
	extrasChanged := false
	if extraProvided {
		// validate extra ports
		raw := ""
		switch v := req.ExtraPorts.(type) {
		case string:
			raw = v
		case []any:
			parts := []string{}
			for _, e := range v {
				switch x := e.(type) {
				case float64:
					parts = append(parts, strconv.Itoa(int(x)))
				case int:
					parts = append(parts, strconv.Itoa(x))
				case string:
					parts = append(parts, strings.TrimSpace(x))
				}
			}
			raw = strings.Join(parts, ",")
		case []float64:
			parts := []string{}
			for _, e := range v {
				parts = append(parts, strconv.Itoa(int(e)))
			}
			raw = strings.Join(parts, ",")
		}
		vp := policy.ParseExtraPorts(raw, ovpnPort)
		policy.WritePortsState(vp)
		policy.SyncNATConfig(ovpnPort, vp)
		extrasChanged = true
	}
	effectiveExtras := policy.PortsEffective([]int{})
	if len(effectiveExtras) == 0 {
		effectiveExtras = policy.ParseExtraPorts("", ovpnPort)
	}
	// rewrite remote lines in template
	newTmpl := policy.RewritePushDNS(originalTmpl, nil) // noop-ish; we handle remote separately
	_ = newTmpl
	// Rebuild template remote block
	remoteLines := RemoteLines(tunnelAddr, ovpnPort)
	// simple replacement: replace lines starting with remote
	tmplLines := strings.Split(originalTmpl, "\n")
	var tmplOut []string
	for _, ln := range tmplLines {
		if strings.HasPrefix(strings.TrimSpace(ln), "remote ") {
			continue
		}
		tmplOut = append(tmplOut, ln)
	}
	// insert remote lines after proto line
	inserted := false
	var finalTmpl []string
	for _, ln := range tmplOut {
		finalTmpl = append(finalTmpl, ln)
		if strings.HasPrefix(strings.TrimSpace(ln), "proto ") && !inserted {
			for _, r := range strings.Split(remoteLines, "\n") {
				finalTmpl = append(finalTmpl, r)
			}
			inserted = true
		}
	}
	if !inserted {
		for _, r := range strings.Split(remoteLines, "\n") {
			finalTmpl = append(finalTmpl, r)
		}
	}
	// proto replace
	for i, ln := range finalTmpl {
		if strings.HasPrefix(strings.TrimSpace(ln), "proto ") {
			finalTmpl[i] = "proto " + proto
		}
	}
	newTemplate := strings.Join(finalTmpl, "\n")
	tmplChanged := newTemplate != originalTmpl
	if tmplChanged {
		if data, err := os.ReadFile(template); err == nil {
			_ = os.WriteFile(template+".bak", data, 0o644)
		}
		_ = fsx.WriteFileAtomic(template, []byte(newTemplate), 0o644)
	}

	oldTunnelAddr := ""
	for _, line := range strings.Split(originalTmpl, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 3 && fields[0] == "remote" {
			oldTunnelAddr = fields[1]
			break
		}
	}

	if classification != nil {
		classification.RestartRequired = changed || tunnelAddr != oldTunnelAddr
		classification.HotReload = dnsChanged || ipv6Changed || extrasChanged
	}

	// no-op check
	if !confChanged && !tmplChanged && !extrasChanged {
		return true
	}

	// invalidate cached ovpn
	invalidateCachedOVPN()

	restartFailed := false
	if changed {
		if !RestartOpenVPN() {
			restartFailed = true
			// rollback
			// restore from .bak if exists
			if _, err := os.Stat(setting + ".bak"); err == nil {
				// copy back
				bak, _ := os.ReadFile(setting + ".bak")
				os.WriteFile(setting, bak, 0o644)
			}
			if tmplChanged {
				if bak, err := os.ReadFile(template + ".bak"); err == nil {
					os.WriteFile(template, bak, 0o644)
				}
			}
			if RestartOpenVPN() {
				// ok
			}
		}
	} else if confChanged || extrasChanged {
		_ = ReloadOpenVPN()
	}

	// The snapshots served their purpose, whatever happened.
	os.Remove(setting + ".bak")
	os.Remove(template + ".bak")

	if restartFailed {
		return false
	}
	return true
}

func invalidateCachedOVPN() {
	root := openvpnRoot()
	glob := filepath.Join(root, "ovnode", "users", "*", "client.ovpn")
	matches, _ := filepath.Glob(glob)
	for _, m := range matches {
		os.Remove(m)
	}
}
