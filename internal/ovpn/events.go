// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The hook event log is the node's own record of what the max-login hook
// decided. One line per event, "<epoch> [ovnode-mlogin] <message>".
//
// A reject is not automatically an authentication failure. The hook logs
// several distinct situations and the panel used to present all of them as
// "auth errors", which made a deliberately disabled user's reconnect look
// like a security incident. Severities: policy = expected, warn =
// unexplained, failure = the node or the TLS layer is actually broken.

const (
	// SeverityPolicy marks an expected refusal.
	SeverityPolicy = "policy"
	// SeverityWarn marks an unexplained refusal.
	SeverityWarn = "warn"
	// SeverityFailure marks a real authentication or TLS failure.
	SeverityFailure = "failure"
)

// rejectReason maps a token of the hook's line to an action, a severity and
// a human reason.
type rejectReason struct {
	needle   string
	action   string
	severity string
	reason   string
}

var rejectReasons = []rejectReason{
	{"is disabled", "disabled", SeverityPolicy, "user disabled in the panel"},
	{"disabled;", "disabled", SeverityPolicy, "user disabled in the panel"},
	{"USERS_DIR missing", "fail_closed", SeverityFailure, "node user state missing"},
	{"could not verify", "takeover_failed", SeverityFailure, "old session not terminated"},
	{"management unavailable", "mgmt_degraded", SeverityWarn, "management unavailable"},
	{"GLOBAL_CHECK_FAILED", "global_check", SeverityPolicy, "panel policy check failed"},
	{"GLOBAL_REJECT", "global_policy", SeverityPolicy, "panel rejected the connection"},
	{"max login reached", "max_logins", SeverityPolicy, "max logins reached"},
}

var (
	// limitRe matches the strict max-login line, which carries the limit
	// instead of the words "max login reached".
	limitRe = regexp.MustCompile(`\blimit=`)
	// cnActionRe finds the common name and the hook's verdict in a line.
	cnActionRe = regexp.MustCompile(`CN=([^ ]+).*?(GLOBAL_REJECT|LOCAL_REJECT|REJECT|GLOBAL_CHECK_FAILED)`)
	// tlsErrorRe matches the TLS and authentication failures of the
	// OpenVPN log — the failures that never reach the connect hook.
	tlsErrorRe = regexp.MustCompile(`(?i)(TLS Error|Auth Failed|VERIFY ERROR|CRL has expired|certificate revoked|SSL error)`)
	// openvpnTSRe matches the timestamp of a log line that carries one.
	openvpnTSRe = regexp.MustCompile(`^[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+(.*)$`)
	// peerRe finds the peer address of a log line.
	peerRe = regexp.MustCompile(`\[AF_INET6?\](\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?|\S+:\d+)`)
)

// Event is one classified diagnostic event.
type Event struct {
	TS       float64 `json:"ts"`
	LastSeen float64 `json:"last_seen"`
	// Ongoing is nil for a hook event: the hook knows nothing beyond its
	// line, so the panel decides "ongoing" from the timestamp.
	Ongoing  any    `json:"ongoing"`
	CN       string `json:"cn"`
	Action   string `json:"action"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
	Peer     string `json:"peer"`
	Source   string `json:"source"`
	Count    int    `json:"count,omitempty"`
}

// classifyReject maps a hook line to (action, severity, human reason).
func classifyReject(message string) (string, string, string) {
	for _, r := range rejectReasons {
		if strings.Contains(message, r.needle) {
			return r.action, r.severity, r.reason
		}
	}
	if strings.Contains(message, "REJECT") && limitRe.MatchString(message) {
		return "max_logins", SeverityPolicy, "max logins reached"
	}
	if strings.Contains(message, "REJECT") {
		// Unexplained reject: shown, but never counted as a security failure.
		return "other", SeverityWarn, "unclassified reject"
	}
	if strings.Contains(message, "FAILED") {
		return "check_failed", SeverityWarn, "policy check failed"
	}
	return "event", SeverityPolicy, "session event"
}

// hookEventLogPath returns the path of the hook event log.
func hookEventLogPath() string {
	if v := os.Getenv("OVNODE_LOG_FILE"); v != "" {
		return v
	}
	return "/var/log/ovnode/hook-events.log"
}

type hookEvent struct {
	ts      float64
	message string
}

var (
	eventCacheMu  sync.Mutex
	eventCacheAt  time.Time
	eventCacheKey string
	eventCache    []hookEvent
)

// readHookEvents returns the hook events of the last hours.
//
// The hours are clamped: a client-controlled window used to fork a week-long
// scan, and alternating values defeated the cache. The result is cached for
// a few seconds because the panel polls this route on a timer. The cache is
// keyed by the log file and the window, so a different tree never reads
// another one's events.
func readHookEvents(hours int) []hookEvent {
	bounded := clampHours(hours)
	path := hookEventLogPath()
	key := path + "|" + strconv.Itoa(bounded)
	eventCacheMu.Lock()
	defer eventCacheMu.Unlock()
	if eventCache != nil && eventCacheKey == key && time.Since(eventCacheAt) < 5*time.Second {
		return eventCache
	}
	cutoff := float64(time.Now().Unix()) - float64(bounded)*3600
	var out []hookEvent
	data, err := os.ReadFile(path)
	if err == nil {
		for _, raw := range strings.Split(string(data), "\n") {
			if raw == "" {
				continue
			}
			head, msg, _ := strings.Cut(raw, " ")
			ts, err := strconv.ParseFloat(head, 64)
			if err != nil {
				continue
			}
			if ts < cutoff {
				continue
			}
			out = append(out, hookEvent{ts: ts, message: msg})
		}
	}
	eventCache = out
	eventCacheKey = key
	eventCacheAt = time.Now()
	return out
}

// clampHours bounds the event window to a day.
func clampHours(hours int) int {
	if hours < 1 {
		return 1
	}
	if hours > 24 {
		return 24
	}
	return hours
}

// openvpnLogLines returns the tail of the OpenVPN log.
//
// Only the tail: the log is append-only and unbounded, and the panel polls
// this on a timer.
func openvpnLogLines() []string {
	path := filepath.Join(openvpnRoot(), "server", "openvpn.log")
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	const maxTail = 256 * 1024
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	start := int64(0)
	if info.Size() > maxTail {
		start = info.Size() - maxTail
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	if start > 0 {
		// Drop the partial first line the tail starts in the middle of.
		if i := strings.IndexByte(string(data), '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

// tlsSeenPath returns the path of the per-failure first/last-seen state.
func tlsSeenPath() string {
	return filepath.Join(ovnodeStateDir(), "tls_seen.json")
}

// ovnodeStateDir returns the node's own state directory.
func ovnodeStateDir() string {
	return filepath.Join(openvpnRoot(), "ovnode", "state")
}

type tlsSeen struct {
	First float64 `json:"first"`
	Last  float64 `json:"last"`
}

func loadTLSSeen() map[string]tlsSeen {
	out := map[string]tlsSeen{}
	data, err := os.ReadFile(tlsSeenPath())
	if err != nil {
		return out
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return map[string]tlsSeen{}
	}
	return out
}

func saveTLSSeen(seen map[string]tlsSeen) {
	dir := ovnodeStateDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	data, err := json.Marshal(seen)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".tls_seen-*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	if err := os.Rename(tmpName, tlsSeenPath()); err != nil {
		_ = os.Remove(tmpName)
		return
	}
}

// openvpnLogEvents returns the real TLS and authentication failures.
//
// The hook never sees them: a bad certificate or a failed handshake does not
// reach client-connect, so the OpenVPN log is the only place they appear and
// they are the only events that justify a danger badge.
//
// The log carries no timestamps on this build, so the times are the ones
// this agent observed: first and last seen per distinct failure, kept in a
// small state file.
func openvpnLogEvents(hours int) []Event {
	now := float64(time.Now().Unix())
	window := float64(clampHours(hours)) * 3600
	type fingerprint struct {
		count  int
		first  float64
		last   float64
		peer   string
		reason string
	}
	fingerprints := map[string]*fingerprint{}
	for _, line := range openvpnLogLines() {
		if !tlsErrorRe.MatchString(line) {
			continue
		}
		peer := "?"
		if m := peerRe.FindStringSubmatch(line); m != nil {
			peer = m[1]
		}
		// Peer and kind is the identity that matters: one scanner retrying
		// is one problem, not N log lines.
		kind := "tls"
		if strings.Contains(line, "Auth Failed") {
			kind = "auth"
		}
		key := peer + "|" + kind
		detail := line
		if i := strings.Index(line, ": "); i >= 0 {
			detail = line[i+2:]
		}
		if len(detail) > 160 {
			detail = detail[:160]
		}
		lineTS := 0.0
		if m := openvpnTSRe.FindStringSubmatch(line); m != nil {
			// The stamped time is a wall clock: it is read as local time,
			// the way the agent that wrote it meant it.
			if t, err := time.ParseInLocation("Jan 2 15:04:05 2006",
				m[1]+" "+m[2]+" "+m[3]+" "+m[4], time.Local); err == nil {
				lineTS = float64(t.Unix())
			}
			// A stamped line can be aged out exactly. An unstamped one
			// cannot: it is in the log now.
			if lineTS > 0 && now-lineTS > window {
				continue
			}
		}
		entry := fingerprints[key]
		if entry == nil {
			entry = &fingerprint{count: 1, first: lineTS, last: lineTS, peer: peer, reason: detail}
			if entry.first == 0 {
				entry.first = now
			}
			if entry.last == 0 {
				entry.last = now
			}
			fingerprints[key] = entry
			continue
		}
		entry.count++
		if lineTS > 0 {
			if lineTS > entry.last {
				entry.last = lineTS
			}
			if entry.first == 0 || lineTS < entry.first {
				entry.first = lineTS
			}
		} else {
			entry.last = now
		}
	}
	if len(fingerprints) == 0 {
		// Nothing in the log: drop the recorded times, so a failure that
		// stopped does not stay "ongoing" forever.
		saveTLSSeen(map[string]tlsSeen{})
		return nil
	}
	seen := loadTLSSeen()
	events := make([]Event, 0, len(fingerprints))
	for key, entry := range fingerprints {
		prior := seen[key]
		first := entry.first
		if first == 0 {
			first = prior.First
		}
		if first == 0 {
			first = now
		}
		last := entry.last
		if prior.Last > last {
			last = prior.Last
		}
		// Present in this poll AND in the previous one: still happening.
		ongoing := false
		if prior.Last > 0 && now-prior.Last <= window/2 {
			ongoing = true
		}
		action := "tls"
		if strings.HasSuffix(key, "|auth") {
			action = "tls_auth"
		}
		events = append(events, Event{
			TS:       first,
			LastSeen: last,
			Ongoing:  ongoing,
			CN:       "",
			Action:   action,
			Severity: SeverityFailure,
			Reason:   entry.reason,
			Peer:     entry.peer,
			Source:   "openvpn",
			Count:    entry.count,
		})
	}
	// Bounded by construction: whatever is not in this poll is forgotten.
	next := map[string]tlsSeen{}
	for key, entry := range fingerprints {
		next[key] = tlsSeen{First: entry.first, Last: entry.last}
	}
	saveTLSSeen(next)
	return events
}
