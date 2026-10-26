// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ovnode/internal/logging"
	"ovnode/internal/pki"
	"ovnode/internal/store"
)

// Session matching is dynamic-IP safe: a session marker is live when its
// (common name, pool IP) pair appears in the status file — the pool IP is
// stable for the lifetime of a session, unlike the client's real IP:port,
// which changes on every reconnect. Real-address matching is kept only as a
// fallback for markers that predate pool-IP keying.

// StatusFile returns the path of the OpenVPN status file.
func StatusFile() string {
	return filepath.Join(openvpnRoot(), "server", "status.log")
}

// marker is one session marker on disk.
type marker struct {
	key         string
	commonName  string
	trustedIP   string
	trustedPort string
	poolIP      string
	created     int64
}

// readMarkers returns the session markers of the tree.
//
// The lock files of the store are skipped: they are named like a marker but
// carry no session.
func readMarkers() []marker {
	dir := pki.SessionsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []marker
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		m, ok := store.ReadMarker(filepath.Join(dir, name))
		if !ok {
			continue
		}
		cn := m.CommonName
		if cn == "" {
			cn = name
			if i := strings.Index(name, "."); i >= 0 {
				cn = name[:i]
			}
		}
		out = append(out, marker{
			key:         name,
			commonName:  cn,
			trustedIP:   m.TrustedIP,
			trustedPort: m.TrustedPort,
			poolIP:      m.PoolIP,
			created:     m.Created,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// liveIndex is the O(1) lookup set for marker matching.
type liveIndex struct {
	pool map[string]bool
	real map[string]bool
}

func newLiveIndex(sessions []Session) liveIndex {
	idx := liveIndex{pool: map[string]bool{}, real: map[string]bool{}}
	for _, s := range sessions {
		idx.pool[s.CommonName+"|"+s.VirtualAddress] = true
		idx.real[s.CommonName+"|"+s.TrustedIP+"|"+s.TrustedPort] = true
	}
	return idx
}

// isLive reports whether a marker corresponds to a session in the status
// file.
//
// Primary match: (common name, pool IP). Fallback for a marker without a
// pool IP: (common name, real ip:port).
func (m marker) isLive(idx liveIndex) bool {
	if m.poolIP != "" {
		return idx.pool[m.commonName+"|"+m.poolIP]
	}
	return idx.real[m.commonName+"|"+m.trustedIP+"|"+m.trustedPort]
}

// sessionRow is the JSON shape of a live session.
func sessionRow(s Session) map[string]any {
	return map[string]any{
		"common_name":     s.CommonName,
		"trusted_ip":      s.TrustedIP,
		"trusted_port":    s.TrustedPort,
		"virtual_address": s.VirtualAddress,
		"bytes_received":  s.BytesReceived,
		"bytes_sent":      s.BytesSent,
		"client_id":       s.ClientID,
	}
}

// markerRow is the JSON shape of a session marker.
func (m marker) markerRow() map[string]any {
	return map[string]any{
		"session_key":             m.key,
		"common_name":             m.commonName,
		"trusted_ip":              m.trustedIP,
		"trusted_port":            m.trustedPort,
		"ifconfig_pool_remote_ip": m.poolIP,
		"created":                 m.created,
	}
}

// UserDiagnostics returns the session diagnostics in the shape the panel
// consumes.
//
// Panel consumers of GET /sync/sessions data:
//
//   - live_sessions      — the node diagnostics and the stale-session sweep
//   - sessions           — the SPA sessions tab (an alias of live_sessions)
//   - stale_markers      — the stale-session sweep
//   - live_count / stale_marker_count / auth_errors / rejects — the metrics
//   - auth_errors_by_cn  — the login health summary, which looks counts up
//     by panel USERNAME, so the common names are mapped here
//   - events             — the classified events (ts, cn, action, severity,
//     reason, peer); only "failure" is a real auth or TLS problem
func UserDiagnostics(commonName string, hours int) map[string]any {
	sessions := ParseSessions(StatusFile())
	idx := newLiveIndex(sessions)
	markers := readMarkers()

	live := []map[string]any{}
	for _, s := range sessions {
		if commonName != "" && s.CommonName != commonName {
			continue
		}
		live = append(live, sessionRow(s))
	}
	active := []map[string]any{}
	stale := []map[string]any{}
	for _, m := range markers {
		if commonName != "" && m.commonName != commonName {
			continue
		}
		if m.isLive(idx) {
			active = append(active, m.markerRow())
		} else {
			stale = append(stale, m.markerRow())
		}
	}

	rejects := map[string]int{}
	globalRejects := map[string]int{}
	authErrors := map[string]int{}
	rejectsByReason := map[string]int{}
	lastErrors := map[string]string{}
	lastEventTS := map[string]float64{}
	events := []Event{}

	for _, ev := range readHookEvents(hours) {
		m := cnActionRe.FindStringSubmatch(ev.message)
		if m == nil {
			continue
		}
		cn, hookAction := m[1], m[2]
		if commonName != "" && cn != commonName {
			continue
		}
		action, severity, reason := classifyReject(ev.message)
		rejects[cn]++
		rejectsByReason[reason]++
		if hookAction == "GLOBAL_REJECT" {
			globalRejects[cn]++
		}
		if severity == SeverityFailure {
			authErrors[cn]++
		}
		lastErrors[cn] = ev.message
		if ev.ts > lastEventTS[cn] {
			lastEventTS[cn] = ev.ts
		}
		events = append(events, Event{
			TS:       ev.ts,
			LastSeen: ev.ts,
			Ongoing:  nil,
			CN:       cn,
			Action:   action,
			Severity: severity,
			Reason:   reason,
			Peer:     "",
			Source:   "mlogin",
		})
	}

	// TLS and authentication failures never reach the max-login hook, so
	// they come from the OpenVPN log and are the only events that justify
	// a danger badge.
	tlsTotal := 0
	for _, ev := range openvpnLogEvents(hours) {
		if commonName != "" {
			continue
		}
		rejectsByReason[ev.Reason]++
		authErrors[""]++
		tlsTotal++
		events = append(events, ev)
	}

	// The management socket is how the node drops a session. When it is
	// unusable the node says so: the panel shows it and the operator knows
	// the sessions cannot be killed.
	mgmtUsable := managementAvailable()
	if !mgmtUsable {
		warnManagementUnavailable()
	}
	if commonName == "" && !mgmtUsable {
		now := float64(time.Now().Unix())
		events = append(events, Event{
			TS:       now,
			LastSeen: now,
			Ongoing:  true,
			CN:       "",
			Action:   "mgmt_degraded",
			Severity: SeverityWarn,
			Reason:   "management unavailable",
			Peer:     "",
			Source:   "agent",
		})
	}

	sort.SliceStable(events, func(i, j int) bool { return events[i].TS > events[j].TS })

	policyTotal, warnTotal, failureTotal := 0, 0, 0
	for _, ev := range events {
		switch ev.Severity {
		case SeverityPolicy:
			policyTotal++
		case SeverityWarn:
			warnTotal++
		case SeverityFailure:
			failureTotal++
		}
	}

	// The panel looks the auth counts up by username, so the common names
	// are mapped to the display names here.
	names := store.NameMap(pki.UsersDir())
	display := func(cn string) string {
		if cn == "" {
			return "(tls)"
		}
		if name := names[cn]; name != "" {
			return name
		}
		return cn
	}
	authErrorsByCN := map[string]int{}
	for cn, count := range authErrors {
		authErrorsByCN[display(cn)] += count
	}
	rejectsByCN := map[string]int{}
	for cn, count := range rejects {
		rejectsByCN[display(cn)] += count
	}

	var lastError any
	if commonName != "" {
		if msg, ok := lastErrors[commonName]; ok {
			lastError = msg
		}
	} else {
		lastError = lastErrors
	}

	if len(events) > 100 {
		events = events[:100]
	}

	return map[string]any{
		"common_name":   commonName,
		"live_sessions": live,
		// Alias consumed by the panel frontend (the sessions tab).
		"sessions":            live,
		"active_markers":      active,
		"stale_markers":       stale,
		"live_count":          len(live),
		"active_marker_count": len(active),
		"stale_marker_count":  len(stale),
		// Real authentication and TLS failures only — a disabled user's
		// reconnect is a policy reject and must not raise this counter.
		"auth_errors":          failureTotal,
		"auth_errors_by_cn":    authErrorsByCN,
		"total_events":         policyTotal + warnTotal + failureTotal,
		"policy_rejects":       policyTotal,
		"warn_rejects":         warnTotal,
		"failures":             failureTotal,
		"tls_failures":         tlsTotal,
		"rejects":              sumCounts(rejects),
		"rejects_by_reason":    rejectsByReason,
		"rejects_by_cn":        rejectsByCN,
		"last_event_ts":        lastEventTS,
		"events":               events,
		"global_rejects":       sumCounts(globalRejects),
		"last_error":           lastError,
		"management_available": managementAvailable(),
	}
}

// sumCounts adds the values of a counter map.
func sumCounts(m map[string]int) int {
	total := 0
	for _, v := range m {
		total += v
	}
	return total
}

// managementAvailable probes the management socket of THIS tree.
//
// The liveness check is tree-scoped: a host can run several OpenVPN
// instances, and a socket that belongs to another tree answers but must
// never be driven by this node.
func managementAvailable() bool {
	return mgmtAvailable(time.Now())
}

// ManagementAvailable reports whether the management socket of this tree
// can be used.
// mgmtWarnOnce keeps the degraded warning out of the ring on every poll.
var mgmtWarnOnce sync.Once

// warnManagementUnavailable logs the unusable management socket once.
//
// The panel's log view is where an operator looks, and a socket that is
// down is a warning, not an error: the node still serves every route.
func warnManagementUnavailable() {
	mgmtWarnOnce.Do(func() {
		logging.Warn("the OpenVPN management socket is not usable: sessions cannot be killed")
	})
}

var (
	mgmtAvailMu  sync.Mutex
	mgmtAvailAt  time.Time
	mgmtAvailVal bool
	mgmtAvailSet bool
)

// mgmtAvailable returns the cached liveness of the management socket.
func mgmtAvailable(now time.Time) bool {
	mgmtAvailMu.Lock()
	defer mgmtAvailMu.Unlock()
	if mgmtAvailSet && now.Sub(mgmtAvailAt) < 8*time.Second {
		return mgmtAvailVal
	}
	mgmtAvailVal = probeManagement()
	mgmtAvailAt = now
	mgmtAvailSet = true
	return mgmtAvailVal
}

// probeManagement reports whether the tree's management socket answers.
//
// The tree's OpenVPN must be running first: a foreign daemon may listen on
// the same port, and a node that drove it would kill another node's
// sessions.
func probeManagement() bool {
	if !TreeOpenVPNRunning() {
		return false
	}
	conn, err := dialManagement()
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
