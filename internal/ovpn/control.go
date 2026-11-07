// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"fmt"
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

	// Phase (a): parse + validate the whole request, no I/O.
	// port
	ovpnPort := 0
	switch v := req.OVPNPort.(type) {
	case int:
		ovpnPort = v
	case float64:
		ovpnPort = int(v)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return false
		}
		ovpnPort = n
	default:
		// missing port is not allowed
		return false
	}
	if ovpnPort < 1 || ovpnPort > 65535 {
		return false
	}
	if policy.IsReservedPrimaryPort(ovpnPort) {
		return false
	}

	// protocol
	proto, ok := normalizeProto(req.Protocol)
	if !ok {
		return false
	}

	// tunnel address validation (empty is resolved later)
	tunnelAddr := strings.TrimSpace(req.TunnelAddress)
	if tunnelAddr != "" && !tunnelRe.MatchString(tunnelAddr) {
		return false
	}

	// DNS
	dnsProvided := req.DNS1 != nil || req.DNS2 != nil
	dns1 := ""
	dns2 := ""
	hasDNS1 := req.DNS1 != nil
	hasDNS2 := req.DNS2 != nil
	if hasDNS1 {
		v := policy.ValidateIP(*req.DNS1)
		if *req.DNS1 != "" && v == "" {
			return false
		}
		dns1 = v
	}
	if hasDNS2 {
		v := policy.ValidateIP(*req.DNS2)
		if *req.DNS2 != "" && v == "" {
			return false
		}
		dns2 = v
	}

	// IPv6
	ipv6Provided := req.EnableIPv6 != nil || req.IPv6Prefix != nil
	curEn, curPref := policy.IPv6Effective(IPv6Enabled(), IPv6Prefix())
	enableIPv6 := curEn
	if req.EnableIPv6 != nil {
		enableIPv6 = *req.EnableIPv6
	}
	ipv6Prefix := curPref
	if req.IPv6Prefix != nil {
		v := policy.ValidatePrefix(*req.IPv6Prefix)
		if v == "" {
			return false
		}
		ipv6Prefix = v
	}

	// extra ports
	extraProvided := req.ExtraPorts != nil
	var extraPorts []int
	if extraProvided {
		raw, ok := extraPortsRaw(req.ExtraPorts)
		if !ok {
			return false
		}
		vp, err := policy.ValidateExtraPorts(raw, ovpnPort)
		if err != nil {
			return false
		}
		extraPorts = vp
	}

	// Phase (b): read files and compute new content in memory.
	data, err := os.ReadFile(setting)
	if err != nil {
		return false
	}
	config := string(data)
	tmplData, _ := os.ReadFile(template)
	originalTmpl := string(tmplData)

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

	// DNS rewrite (in memory)
	dnsChanged := false
	d1, d2 := VPNDNS()
	if hasDNS1 {
		d1 = dns1
	}
	if hasDNS2 {
		d2 = dns2
	}
	if dnsProvided {
		def1, def2 := VPNDNS()
		dnsDesired := policy.DNSEffective(def1, def2)
		if hasDNS1 {
			if dns1 != "" {
				dnsDesired = []string{dns1}
				if hasDNS2 && dns2 != "" {
					dnsDesired = append(dnsDesired, dns2)
				}
			} else {
				dnsDesired = []string{}
				if hasDNS2 && dns2 != "" {
					dnsDesired = append(dnsDesired, dns2)
				}
			}
		}
		newConfig = policy.RewritePushDNS(newConfig, dnsDesired)
	}

	// IPv6 rewrite (in memory)
	ipv6Changed := false
	if ipv6Provided {
		newConfig, ipv6Changed = applyIPv6(newConfig, enableIPv6, ipv6Prefix)
	}

	// tunnel address resolution
	oldTunnelAddr := ""
	for _, line := range strings.Split(originalTmpl, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 3 && fields[0] == "remote" {
			oldTunnelAddr = fields[1]
			break
		}
	}
	if tunnelAddr == "" {
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

	// effective extras for remote lines
	effectiveExtras := extraPorts
	if !extraProvided {
		effectiveExtras = policy.PortsEffective(ExtraVPNPorts())
	}

	// template rewrite
	tmplLines := strings.Split(originalTmpl, "\n")
	var tmplOut []string
	for _, ln := range tmplLines {
		if strings.HasPrefix(strings.TrimSpace(ln), "remote ") {
			continue
		}
		tmplOut = append(tmplOut, ln)
	}
	// build remote lines for primary + extras
	remotePortList := []int{ovpnPort}
	remotePortList = append(remotePortList, effectiveExtras...)
	remoteLines := make([]string, 0, len(remotePortList))
	for _, p := range remotePortList {
		remoteLines = append(remoteLines, "remote "+tunnelAddr+" "+strconv.Itoa(p))
	}
	inserted := false
	var finalTmpl []string
	for _, ln := range tmplOut {
		finalTmpl = append(finalTmpl, ln)
		if strings.HasPrefix(strings.TrimSpace(ln), "proto ") && !inserted {
			finalTmpl = append(finalTmpl, remoteLines...)
			inserted = true
		}
	}
	if !inserted {
		finalTmpl = append(finalTmpl, remoteLines...)
	}
	for i, ln := range finalTmpl {
		if strings.HasPrefix(strings.TrimSpace(ln), "proto ") {
			finalTmpl[i] = "proto " + proto
		}
	}
	newTemplate := strings.Join(finalTmpl, "\n")
	tmplChanged := newTemplate != originalTmpl
	confChanged := newConfig != config

	dnsStateChanged := false
	if dnsProvided {
		st := policy.ReadDNSState()
		dnsStateChanged = st.DNS1 != d1 || st.DNS2 != d2
	}
	ipv6StateChanged := false
	if ipv6Provided {
		en, pref := policy.IPv6Effective(IPv6Enabled(), IPv6Prefix())
		ipv6StateChanged = en != enableIPv6 || pref != ipv6Prefix
	}
	portsStateChanged := false
	if extraProvided {
		portsStateChanged = !intsEqual(policy.PortsEffective(ExtraVPNPorts()), extraPorts)
	}

	anyChange := confChanged || tmplChanged || dnsStateChanged || ipv6StateChanged || portsStateChanged

	// no-op fast path
	if !anyChange {
		if classification != nil {
			classification.RestartRequired = changed || tunnelAddr != oldTunnelAddr
			classification.HotReload = false
		}
		return true
	}

	// Phase (c): apply with snapshots + rollback.
	snapshots := []snapshot{}
	snap := func(path string) {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			if s, err := snapshotFile(path); err == nil {
				snapshots = append(snapshots, s)
			}
		} else {
			// remember non-existent path for removal on rollback
			snapshots = append(snapshots, snapshot{path: path, existed: false})
		}
	}
	snap(setting)
	snap(template)
	if dnsProvided {
		snap(policy.DNSStatePath())
	}
	if ipv6Provided {
		snap(policy.IPv6StatePath())
	}
	if extraProvided {
		snap(policy.PortsStatePath())
		snap("/etc/default/ovnode-nat")
	}
	defer func() {
		for i := len(snapshots) - 1; i >= 0; i-- {
			_ = snapshots[i].cleanup()
		}
	}()

	applyErr := func() error {
		if confChanged {
			if err := fsx.WriteFileAtomic(setting, []byte(newConfig), 0o644); err != nil {
				return err
			}
		}
		if tmplChanged {
			if err := fsx.WriteFileAtomic(template, []byte(newTemplate), 0o644); err != nil {
				return err
			}
		}
		if dnsProvided {
			if policy.WriteDNSState(d1, d2) {
				dnsChanged = true
			}
		}
		if ipv6Provided {
			if policy.WriteIPv6State(enableIPv6, ipv6Prefix) {
				ipv6Changed = true
			}
		}
		if extraProvided {
			policy.WritePortsState(extraPorts)
			if err := policy.SyncNATConfig(ovpnPort, extraPorts); err != nil {
				return err
			}
		}
		if dnsProvided {
			if st := policy.ReadDNSState(); st.DNS1 != d1 || st.DNS2 != d2 {
				return fmt.Errorf("dns state was not written")
			}
		}
		if extraProvided {
			if !intsEqual(policy.ReadPortsState().Ports, extraPorts) {
				return fmt.Errorf("ports state was not written")
			}
		}
		return nil
	}()
	if applyErr != nil {
		restoreSnapshots(snapshots)
		return false
	}

	invalidateCachedOVPN()

	restartRequired := changed || tunnelAddr != oldTunnelAddr
	hotReload := dnsChanged || ipv6Changed || portsStateChanged

	restartFailed := false
	if restartRequired {
		if OpenVPNIsRunning() && !RestartOpenVPN() {
			restartFailed = true
		}
	} else if confChanged {
		if OpenVPNIsRunning() && !ReloadOpenVPN() {
			restartFailed = true
		}
	}

	if restartFailed {
		restoreSnapshots(snapshots)
		// attempt restart/reload again (best effort)
		if restartRequired {
			_ = RestartOpenVPN()
		} else {
			_ = ReloadOpenVPN()
		}
		if classification != nil {
			classification.RestartRequired = restartRequired
			classification.HotReload = hotReload
		}
		return false
	}

	if classification != nil {
		classification.RestartRequired = restartRequired
		classification.HotReload = hotReload
	}
	return true
}

func normalizeProto(p string) (string, bool) {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return "tcp", true
	}
	switch p {
	case "tcp", "tcp4", "tcp6":
		return "tcp", true
	case "udp", "udp4", "udp6":
		return "udp", true
	default:
		return "", false
	}
}

func applyIPv6(conf string, enabled bool, prefix string) (string, bool) {
	lines := strings.Split(conf, "\n")
	hasTun := false
	hasServer := false
	serverIdx := -1
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		if t == "tun-ipv6" {
			hasTun = true
		}
		if strings.HasPrefix(t, "server-ipv6 ") {
			hasServer = true
			serverIdx = i
		}
	}
	changed := false
	if !enabled {
		out := []string{}
		for _, ln := range lines {
			t := strings.TrimSpace(ln)
			if t == "tun-ipv6" || strings.HasPrefix(t, "server-ipv6 ") {
				changed = true
				continue
			}
			out = append(out, ln)
		}
		return strings.Join(out, "\n"), changed
	}
	// enabled
	if !hasTun {
		lines = append(lines, "tun-ipv6")
		changed = true
	}
	if hasServer {
		if strings.TrimSpace(lines[serverIdx]) != "server-ipv6 "+prefix {
			lines[serverIdx] = "server-ipv6 " + prefix
			changed = true
		}
	} else {
		lines = append(lines, "server-ipv6 "+prefix)
		changed = true
	}
	return strings.Join(lines, "\n"), changed
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

type snapshot struct {
	path    string
	tmp     string
	existed bool
	data    []byte
	mode    os.FileMode
}

func snapshotFile(path string) (snapshot, error) {
	st, err := os.Stat(path)
	if err != nil {
		return snapshot{path: path, existed: false}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot{}, err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".snap-*")
	if err != nil {
		return snapshot{}, err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return snapshot{}, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return snapshot{}, err
	}
	_ = os.Chmod(tmp, st.Mode().Perm())
	return snapshot{path: path, tmp: tmp, existed: true, data: data, mode: st.Mode().Perm()}, nil
}

func (s snapshot) restore() {
	if s.existed {
		_ = os.Rename(s.tmp, s.path)
	} else {
		_ = os.Remove(s.path)
	}
}

func (s snapshot) cleanup() error {
	// restore already called by caller if needed; cleanup just removes temp
	if s.existed {
		_ = os.Remove(s.tmp)
	}
	return nil
}

func restoreSnapshots(snaps []snapshot) {
	for i := len(snaps) - 1; i >= 0; i-- {
		snaps[i].restore()
	}
}

func invalidateCachedOVPN() {
	glob := filepath.Join(fsx.UsersDir(), "*", "client.ovpn")
	matches, _ := filepath.Glob(glob)
	for _, m := range matches {
		os.Remove(m)
	}
}

func intsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
