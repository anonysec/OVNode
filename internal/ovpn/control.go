// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"encoding/json"
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

// cfgChange is the validated form of a ChangeConfigRequest. Fields carry
// what the panel pushed plus the defaults resolved from the current tree.
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

// remoteHost reads the host of the first remote line of a client template.
func remoteHost(tmpl string) string {
	for _, line := range strings.Split(tmpl, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 3 && fields[0] == "remote" {
			return fields[1]
		}
	}
	return ""
}

var tunnelRe = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

var (
	protoRe      = regexp.MustCompile(`(?m)^proto\s+(\S+)`)
	portRe       = regexp.MustCompile(`(?m)^port\s+(\d+)`)
	portSetRe    = regexp.MustCompile(`(?m)^port\s+\d+`)
	protoSetRe   = regexp.MustCompile(`(?m)^proto\s+\S+`)
	exitNotifyRe = regexp.MustCompile(`(?m)^explicit-exit-notify\s+\d+`)
)

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

// parseConfigRequest validates the request without touching the disk.
// It returns the changes, or a specific validation message the panel
// can surface.
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
	case intOrString:
		ovpnPort = int(v)
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
		return c, fmt.Errorf("protocol must be tcp or udp")
	}
	c.proto = proto
	c.tunnelAddr = strings.TrimSpace(req.TunnelAddress)
	if c.tunnelAddr != "" && !tunnelRe.MatchString(c.tunnelAddr) {
		return c, fmt.Errorf("tunnel_address is malformed")
	}
	return c, nil
}

func parseDNS(req ChangeConfigRequest, c *cfgChange) error {
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
	curEn, curPref := policy.IPv6Effective(IPv6Enabled(), IPv6Prefix())
	c.enableIPv6 = curEn
	if req.EnableIPv6 != nil {
		c.enableIPv6 = *req.EnableIPv6
	}
	c.ipv6Prefix = curPref
	c.ipv6Provided = req.EnableIPv6 != nil || req.IPv6Prefix != nil
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

// renderServerConf renders the new server.conf from the current content:
// port, proto, explicit-exit-notify, push dns, ipv6.
func renderServerConf(cur string, c cfgChange) string {
	newConfig := portSetRe.ReplaceAllString(cur, "port "+strconv.Itoa(c.ovpnPort))
	newConfig = protoSetRe.ReplaceAllString(newConfig, "proto "+c.proto)
	exitVal := "0"
	if c.proto == "udp" {
		exitVal = "1"
	}
	newConfig = exitNotifyRe.ReplaceAllString(newConfig, "explicit-exit-notify "+exitVal)
	if c.dnsProvided {
		def1, def2 := VPNDNS()
		dnsDesired := policy.DNSEffective(def1, def2)
		if c.dns1 != "" {
			dnsDesired = []string{c.dns1}
			if c.dns2 != "" {
				dnsDesired = append(dnsDesired, c.dns2)
			}
		} else if c.dns2 != "" {
			dnsDesired = []string{c.dns2}
		}
		newConfig = policy.RewritePushDNS(newConfig, dnsDesired)
	}
	if c.ipv6Provided {
		newConfig, _ = applyIPv6(newConfig, c.enableIPv6, c.ipv6Prefix)
	}
	return newConfig
}

// renderClientTemplate renders the new client template: proto plus the
// remote lines for the primary and extra ports.
func renderClientTemplate(cur string, c cfgChange) string {
	tmplLines := strings.Split(cur, "\n")
	var tmplOut []string
	for _, ln := range tmplLines {
		if strings.HasPrefix(strings.TrimSpace(ln), "remote ") {
			continue
		}
		tmplOut = append(tmplOut, ln)
	}
	ports := []int{c.ovpnPort}
	ports = append(ports, c.extraPorts...)
	remoteLines := make([]string, 0, len(ports))
	for _, p := range ports {
		remoteLines = append(remoteLines, "remote "+c.tunnelAddr+" "+strconv.Itoa(p))
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
			finalTmpl[i] = "proto " + c.proto
		}
	}
	return strings.Join(finalTmpl, "\n")
}

func ChangeConfig(req ChangeConfigRequest) (ChangeConfigResult, error) {
	changeConfigMu.Lock()
	defer changeConfigMu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			logging.Syslog("ChangeConfig panic: %v", r)
		}
	}()
	c, err := parseConfigRequest(req)
	if err != nil {
		return ChangeConfigResult{}, err
	}
	return applyConfigChange(c)
}

// applyConfigChange applies a validated change: snapshot, write, rollback
// on failure, and the restart/reload decision.
func applyConfigChange(c cfgChange) (ChangeConfigResult, error) {
	setting := settingFile()
	template := templateFile()
	data, err := os.ReadFile(setting)
	if err != nil {
		return ChangeConfigResult{}, fmt.Errorf("could not read server configuration")
	}
	config := string(data)
	tmplData, _ := os.ReadFile(template)
	originalTmpl := string(tmplData)

	plan := planChange(config, originalTmpl, c)
	if !plan.anyChange {
		return ChangeConfigResult{RestartRequired: plan.restartRequired, HotReload: false}, nil
	}

	snapshots := planSnapshots(c)
	defer func() {
		for i := len(snapshots) - 1; i >= 0; i-- {
			_ = snapshots[i].cleanup()
		}
	}()

	if err := writeChange(plan); err != nil {
		restoreSnapshots(snapshots)
		return ChangeConfigResult{}, err
	}

	invalidateCachedOVPN()

	restartFailed := false
	if plan.restartRequired {
		if OpenVPNIsRunning() && !RestartOpenVPN() {
			restartFailed = true
		}
	} else if plan.confChanged {
		if OpenVPNIsRunning() && !ReloadOpenVPN() {
			restartFailed = true
		}
	}

	if restartFailed {
		restoreSnapshots(snapshots)
		if plan.restartRequired {
			_ = RestartOpenVPN()
		} else {
			_ = ReloadOpenVPN()
		}
		return ChangeConfigResult{RestartRequired: plan.restartRequired, HotReload: plan.hotReload},
			fmt.Errorf("OpenVPN restart failed")
	}

	return ChangeConfigResult{RestartRequired: plan.restartRequired, HotReload: plan.hotReload}, nil
}

type changePlan struct {
	c               cfgChange
	config          string
	newConfig       string
	newTemplate     string
	oldTunnelAddr   string
	confChanged     bool
	tmplChanged     bool
	restartRequired bool
	hotReload       bool
	anyChange       bool
	d1, d2          string
	setting         string
	template        string
}

func planChange(config, originalTmpl string, c cfgChange) changePlan {
	oldProto, oldPort := currentPortProto(config)
	changed := !strings.HasPrefix(oldProto, c.proto) || oldPort != strconv.Itoa(c.ovpnPort)
	newConfig := renderServerConf(config, c)
	oldTunnelAddr := resolveTunnel(originalTmpl, &c)
	if !c.extraProvided {
		c.extraPorts = policy.PortsEffective(ExtraVPNPorts())
	}
	newTemplate := renderClientTemplate(originalTmpl, c)
	d1, d2 := dnsPair(c)
	dnsStateChanged, ipv6StateChanged, portsStateChanged := stateChanges(c, d1, d2)
	tmplChanged := newTemplate != originalTmpl
	confChanged := newConfig != config
	anyChange := confChanged || tmplChanged || dnsStateChanged || ipv6StateChanged || portsStateChanged
	return changePlan{
		c: c, config: config, newConfig: newConfig, newTemplate: newTemplate,
		oldTunnelAddr: oldTunnelAddr, confChanged: confChanged, tmplChanged: tmplChanged,
		restartRequired: changed || c.tunnelAddr != oldTunnelAddr,
		hotReload:       dnsStateChanged || portsStateChanged || (c.ipv6Provided && ipv6StateChanged),
		anyChange:       anyChange,
		d1:              d1, d2: d2, setting: settingFile(), template: templateFile(),
	}
}

func currentPortProto(config string) (proto, port string) {
	if m := protoRe.FindStringSubmatch(config); len(m) > 1 {
		proto = m[1]
	}
	if m := portRe.FindStringSubmatch(config); len(m) > 1 {
		port = m[1]
	}
	return proto, port
}

func resolveTunnel(originalTmpl string, c *cfgChange) string {
	old := remoteHost(originalTmpl)
	if c.tunnelAddr != "" {
		return old
	}
	c.tunnelAddr = old
	if c.tunnelAddr == "" || c.tunnelAddr == "UPDATE_VIA_PANEL" {
		c.tunnelAddr = NodePublicIP()
	}
	return old
}

func dnsPair(c cfgChange) (string, string) {
	d1, d2 := VPNDNS()
	if !c.dnsProvided {
		return d1, d2
	}
	if c.dns1 != "" {
		d1 = c.dns1
	}
	if c.dns2 != "" {
		d2 = c.dns2
	}
	return d1, d2
}

func stateChanges(c cfgChange, d1, d2 string) (dns, ipv6, ports bool) {
	st := policy.ReadDNSState()
	dns = c.dnsProvided && (st.DNS1 != d1 || st.DNS2 != d2)
	if c.ipv6Provided {
		en, pref := policy.IPv6Effective(IPv6Enabled(), IPv6Prefix())
		ipv6 = en != c.enableIPv6 || pref != c.ipv6Prefix
	}
	if c.extraProvided {
		ports = !intsEqual(policy.PortsEffective(ExtraVPNPorts()), c.extraPorts)
	}
	return dns, ipv6, ports
}

func planSnapshots(c cfgChange) []snapshot {
	var snapshots []snapshot
	snap := func(path string) {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			if s, err := snapshotFile(path); err == nil {
				snapshots = append(snapshots, s)
			}
		} else {
			snapshots = append(snapshots, snapshot{path: path, existed: false})
		}
	}
	snap(settingFile())
	snap(templateFile())
	if c.dnsProvided {
		snap(policy.DNSStatePath())
	}
	if c.ipv6Provided {
		snap(policy.IPv6StatePath())
	}
	if c.extraProvided {
		snap(policy.PortsStatePath())
		snap("/etc/default/ovnode-nat")
	}
	return snapshots
}

func writeChange(p changePlan) error {
	if p.confChanged {
		if err := fsx.WriteFileAtomic(p.setting, []byte(p.newConfig), 0o644); err != nil {
			return err
		}
	}
	if p.tmplChanged {
		if err := fsx.WriteFileAtomic(p.template, []byte(p.newTemplate), 0o644); err != nil {
			return err
		}
	}
	if p.c.dnsProvided {
		policy.WriteDNSState(p.d1, p.d2)
	}
	if p.c.ipv6Provided {
		policy.WriteIPv6State(p.c.enableIPv6, p.c.ipv6Prefix)
	}
	if p.c.extraProvided {
		policy.WritePortsState(p.c.extraPorts)
		if err := policy.SyncNATConfig(p.c.ovpnPort, p.c.extraPorts); err != nil {
			return err
		}
	}
	if p.c.dnsProvided {
		if st := policy.ReadDNSState(); st.DNS1 != p.d1 || st.DNS2 != p.d2 {
			return fmt.Errorf("dns state was not written")
		}
	}
	if p.c.extraProvided {
		if !intsEqual(policy.ReadPortsState().Ports, p.c.extraPorts) {
			return fmt.Errorf("ports state was not written")
		}
	}
	return nil
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

// ports decodes the panel's extra_ports field: a plain string, a list of
// numbers, or a list of numeric strings, all joined then validated by
// policy.ValidateExtraPorts.
type ports struct{ raw string }

func (p *ports) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		p.raw = v
		return nil
	}
	var arr []any
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	parts := make([]string, 0, len(arr))
	for _, e := range arr {
		switch x := e.(type) {
		case string:
			parts = append(parts, strings.TrimSpace(x))
		case float64:
			parts = append(parts, strconv.Itoa(int(x)))
		case int:
			parts = append(parts, strconv.Itoa(x))
		default:
			return fmt.Errorf("extra_ports item is not a number or string")
		}
	}
	p.raw = strings.Join(parts, ",")
	return nil
}

// intOrString decodes a port field that may be a JSON number or a numeric
// string.
type intOrString int

func (n *intOrString) UnmarshalJSON(b []byte) error {
	var i int
	if err := json.Unmarshal(b, &i); err == nil {
		*n = intOrString(i)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return err
	}
	*n = intOrString(v)
	return nil
}

func extraPortsRaw(v any) (string, bool) {
	switch val := v.(type) {
	case string:
		return val, true
	case ports:
		return val.raw, true
	case *ports:
		return val.raw, true
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
