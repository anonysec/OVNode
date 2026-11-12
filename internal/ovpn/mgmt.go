// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"fmt"
	"net"

	"os"
	"ovnode/internal/fsx"
	"strconv"
	"strings"
	"time"

	"ovnode/internal/pki"
)

// TakeoverResult is the outcome of a management takeover.
type TakeoverResult int

const (
	// TakeoverVerified: no CLIENT_LIST row is left for the common name.
	TakeoverVerified TakeoverResult = iota
	// TakeoverTimeout: rows remain after the verify budget.
	TakeoverTimeout
	// TakeoverDown: the management socket could not be used.
	TakeoverDown
)

// Budgets. The verify budget is the contract with the operator: a takeover
// must not hold a client handshake longer than this.
const (
	mgmtDialTimeout = 2 * time.Second
	mgmtReplyBudget = 2 * time.Second
	mgmtAuthBudget  = 200 * time.Millisecond
	mgmtBannerIdle  = 150 * time.Millisecond
	mgmtBannerTotal = 1 * time.Second
	statusBudget    = 3 * time.Second
	verifyBudget    = 7 * time.Second
	verifyPoll      = 500 * time.Millisecond
)

// validateMgmtHost refuses non-loopback management hosts unless explicitly
// allowed, because the management password travels in cleartext.
func validateMgmtHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(fsx.Get("AllowRemoteMgmt", "")), "1") {
		return nil
	}
	return fmt.Errorf("management host %q is not loopback; set AllowRemoteMgmt=1", host)
}

// LiveSessionsForCN returns the live sessions of one CN, preferring the
// management socket (status 3) over the status file, which OpenVPN only
// rewrites every few seconds.
func LiveSessionsForCN(statusFile, cn string) []Session {
	if sessions, ok := mgmtSessionsForCN(cn); ok && len(sessions) > 0 {
		return sessions
	}
	// An empty management reply (a parser/version mismatch or a protocol whose
	// socket did not answer) must not hide live sessions: fall back to every
	// selected protocol's status file.
	files := StatusFiles()
	if len(files) == 0 {
		files = []string{statusFile}
	}
	seen := map[string]bool{}
	var out []Session
	for _, file := range files {
		for _, session := range SessionsForCN(file, cn) {
			key := session.CommonName + "|" + session.VirtualAddress
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, session)
		}
	}
	return out
}

// managementTargets is one socket per running protocol.
func managementTargets() []int {
	protos := currentSettings().Protos()
	out := make([]int, 0, len(protos))
	for _, proto := range protos {
		out = append(out, ManagementPort(proto))
	}
	return out
}

// mgmtSessionsForCN runs "status 3" over every protocol's management socket
// and parses the CLIENT_LIST rows. The second result reports whether at
// least one socket answered; callers fall back to the status file when none
// did.
func mgmtSessionsForCN(cn string) ([]Session, bool) {
	var out []Session
	answered := false
	for _, port := range managementTargets() {
		sessions, ok := mgmtSessionsOnPort(port, cn)
		if ok {
			answered = true
			out = append(out, sessions...)
		}
	}
	return out, answered
}

func mgmtSessionsOnPort(port int, cn string) ([]Session, bool) {
	host := mgmtHost()
	if err := validateMgmtHost(host); err != nil {
		return nil, false
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, mgmtDialTimeout)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	m := &mgmtConn{conn: conn}
	if strings.Contains(strings.ToUpper(m.readBanner()), "PASSWORD") {
		pw, ok := readPassword(pki.MgmtPassFile())
		if !ok {
			return nil, false
		}
		_ = conn.SetWriteDeadline(time.Now().Add(mgmtReplyBudget))
		if _, err := conn.Write([]byte(pw + "\n")); err != nil {
			return nil, false
		}
		authReply := m.readUntil(time.Now().Add(mgmtAuthBudget), "SUCCESS", "ERROR")
		upper := strings.ToUpper(authReply)
		if strings.Contains(upper, "BAD PASSWORD") || (strings.Contains(upper, "ERROR") && strings.Contains(upper, "PASSWORD")) {
			return nil, false
		}
	}
	_ = conn.SetWriteDeadline(time.Now().Add(mgmtReplyBudget))
	if _, err := conn.Write([]byte("status 3\n")); err != nil {
		return nil, false
	}
	text := m.readUntil(time.Now().Add(statusBudget), "END")
	_ = conn.SetWriteDeadline(time.Now().Add(mgmtReplyBudget))
	_, _ = conn.Write([]byte("quit\n"))
	if !strings.Contains(text, "END") {
		return nil, false
	}
	return parseMgmtSessions(text, cn), true
}

// parseMgmtSessions parses the status 3 reply into sessions of one CN.
// status 3 uses the CLIENT_LIST,HEADER comma format with the same column
// order as the status file, so the same header-driven parsing applies.
func parseMgmtSessions(text, cn string) []Session {
	columns := make(map[string]int, len(defaultColumns))
	for k, v := range defaultColumns {
		columns[k] = v
	}
	sawHeader := false
	var out []Session
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.Contains(line, "CLIENT_LIST") {
			continue
		}
		// The management "status 3" reply is tab-separated; status files can
		// be comma-separated on older OpenVPN builds.
		delim := "\t"
		if !strings.Contains(line, "\t") {
			delim = ","
		}
		parts := strings.Split(line, delim)
		if strings.HasPrefix(line, "HEADER") {
			if len(parts) > 2 {
				columns = columnMap(parts)
				sawHeader = true
			}
			continue
		}
		if !strings.HasPrefix(line, "CLIENT_LIST") {
			continue
		}
		name := field(parts, columns["Common Name"])
		if name == "" || name != cn {
			continue
		}
		real := field(parts, columns["Real Address"])
		ip, port := splitRealAddress(real)
		out = append(out, Session{
			CommonName:     name,
			RealAddress:    real,
			TrustedIP:      ip,
			TrustedPort:    port,
			VirtualAddress: field(parts, columns["Virtual Address"]),
			BytesReceived:  number(field(parts, columns["Bytes Received"])),
			BytesSent:      number(field(parts, columns["Bytes Sent"])),
			ClientID:       field(parts, columns["Client ID"]),
			ConnectedAt:    connectedAt(field(parts, columns["Connected Since (time_t)"])),
		})
	}
	if !sawHeader {
		// A reply without the CLIENT_LIST header is not a status 3
		// reply: let the caller fall back to the status file.
		return nil
	}
	return out
}

// Takeover kills the given client ids over ONE management connection and
// then verifies that the common name is gone.
//
// One connection for the whole takeover: the management interface asks for
// the password once, so a reconnect storm must not pay for a handshake per
// session. The three results are the hook's three outcomes — verified (the
// old session is gone), timeout (rows remain, the caller refuses) and down
// (the socket could not be used, the caller degrades). A transport failure
// must never refuse a legitimate reconnect.
//
// The returned lines are the log text the hook writes.
func Takeover(host string, port int, passFile, cn string, cids []string) (TakeoverResult, []string) {
	if err := validateMgmtHost(host); err != nil {
		return TakeoverDown, []string{fmt.Sprintf("RESULT DOWN (%s)", err)}
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, mgmtDialTimeout)
	if err != nil {
		return TakeoverDown, []string{fmt.Sprintf("RESULT DOWN (%s)", err)}
	}
	defer conn.Close()
	m := &mgmtConn{conn: conn}

	if strings.Contains(strings.ToUpper(m.readBanner()), "PASSWORD") {
		pw, ok := readPassword(passFile)
		if !ok {
			return TakeoverDown, []string{"RESULT DOWN (management password unreadable)"}
		}
		_ = conn.SetWriteDeadline(time.Now().Add(mgmtReplyBudget))
		if _, err := conn.Write([]byte(pw + "\n")); err != nil {
			return TakeoverDown, []string{fmt.Sprintf("RESULT DOWN (password write failed: %s)", err)}
		}
		authReply := m.readUntil(time.Now().Add(mgmtAuthBudget), "SUCCESS", "ERROR")
		upper := strings.ToUpper(authReply)
		if strings.Contains(upper, "BAD PASSWORD") || (strings.Contains(upper, "ERROR") && strings.Contains(upper, "PASSWORD")) {
			return TakeoverDown, append([]string{}, "RESULT DOWN (bad management password)")
		}
	}

	var lines []string
	for _, cid := range cids {
		cmd := "client-kill " + cid + " max-login-takeover"
		_ = conn.SetWriteDeadline(time.Now().Add(mgmtReplyBudget))
		if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
			lines = append(lines, fmt.Sprintf("KILL FAIL %s (%s)", cmd, err))
			continue
		}
		reply := m.readUntil(time.Now().Add(mgmtReplyBudget), "SUCCESS", "ERROR")
		verdict := "FAIL"
		if strings.Contains(strings.ToUpper(reply), "SUCCESS") {
			verdict = "OK"
		}
		lines = append(lines, fmt.Sprintf("KILL %s %s (%s)", verdict, cmd, shorten(reply, 120)))
	}

	verified := false
	deadline := time.Now().Add(verifyBudget)
	for time.Now().Before(deadline) {
		_ = conn.SetWriteDeadline(time.Now().Add(mgmtReplyBudget))
		if _, err := conn.Write([]byte("status 2\n")); err != nil {
			break
		}
		text := m.readUntil(time.Now().Add(statusBudget), "END")
		if !mgmtHasCN(text, cn) {
			verified = true
			break
		}
		time.Sleep(verifyPoll)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(mgmtReplyBudget))
	_, _ = conn.Write([]byte("quit\n"))

	if verified {
		return TakeoverVerified, append(lines, "RESULT VERIFIED")
	}
	return TakeoverTimeout, append(lines, "RESULT TIMEOUT")
}

// mgmtHost returns the management socket host.
func mgmtHost() string {
	if v := fsx.EnvOr("ManagementHost", ""); v != "" {
		return v
	}
	if v := fsx.EnvOr("ManagementHost", ""); v != "" {
		return v
	}
	return "127.0.0.1"
}

// dialManagement opens a connection to one protocol's management socket.
func dialManagement(port int) (net.Conn, error) {
	host := mgmtHost()
	if err := validateMgmtHost(host); err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	return net.DialTimeout("tcp", addr, mgmtDialTimeout)
}

// SendCommands runs management commands over ONE connection and returns
// their replies.
//
// One connection for the whole batch: the management interface asks for the
// password once, so a mass-kick must not pay a handshake per session.
func SendCommands(cmds []string) ([]string, error) {
	if len(cmds) == 0 {
		return nil, nil
	}
	var (
		all      []string
		firstErr error
		answered bool
	)
	for _, port := range managementTargets() {
		replies, err := sendCommandsTo(port, cmds)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		answered = true
		all = append(all, replies...)
	}
	if !answered {
		return nil, firstErr
	}
	return all, nil
}

// SendCommandsTo runs one batch against a single protocol socket.
func sendCommandsTo(port int, cmds []string) ([]string, error) {
	conn, err := dialManagement(port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	m := &mgmtConn{conn: conn}

	if strings.Contains(strings.ToUpper(m.readBanner()), "PASSWORD") {
		pw, ok := readPassword(pki.MgmtPassFile())
		if !ok {
			return nil, fmt.Errorf("management password unreadable")
		}
		_ = conn.SetWriteDeadline(time.Now().Add(mgmtReplyBudget))
		if _, err := conn.Write([]byte(pw + "\n")); err != nil {
			return nil, err
		}
		authReply := m.readUntil(time.Now().Add(mgmtAuthBudget), "SUCCESS", "ERROR")
		upper := strings.ToUpper(authReply)
		if strings.Contains(upper, "BAD PASSWORD") || (strings.Contains(upper, "ERROR") && strings.Contains(upper, "PASSWORD")) {
			return nil, fmt.Errorf("bad management password")
		}
	}

	replies := make([]string, 0, len(cmds))
	for _, cmd := range cmds {
		_ = conn.SetWriteDeadline(time.Now().Add(mgmtReplyBudget))
		if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
			replies = append(replies, "ERROR: "+err.Error())
			continue
		}
		replies = append(replies, m.readUntil(time.Now().Add(mgmtReplyBudget), "SUCCESS", "ERROR"))
	}
	_ = conn.SetWriteDeadline(time.Now().Add(mgmtReplyBudget))
	_, _ = conn.Write([]byte("quit\n"))
	return replies, nil
}

// mgmtConn is a buffered reader over the management socket.
//
// bufio is not used on purpose: a read deadline that expires inside a
// bufio.Reader is sticky, and the take-over reads the same connection with
// several budgets (banner, password, kill, status).
type mgmtConn struct {
	conn net.Conn
	buf  []byte
}

// fill reads one chunk from the socket into the buffer.
func (m *mgmtConn) fill(deadline time.Time) error {
	_ = m.conn.SetReadDeadline(deadline)
	chunk := make([]byte, 4096)
	n, err := m.conn.Read(chunk)
	if n > 0 {
		m.buf = append(m.buf, chunk[:n]...)
	}
	return err
}

// readBanner reads the management greeting.
//
// The banner and the password prompt usually arrive in one packet, but a
// split packet would leave the prompt unread and every command would be
// answered with "bad password". So the read keeps going until the socket
// goes idle.
func (m *mgmtConn) readBanner() string {
	total := time.Now().Add(mgmtBannerTotal)
	for {
		if strings.Contains(strings.ToUpper(string(m.buf)), "PASSWORD") {
			break
		}
		idle := time.Now().Add(mgmtBannerIdle)
		if idle.After(total) {
			idle = total
		}
		if err := m.fill(idle); err != nil {
			break
		}
	}
	out := string(m.buf)
	m.buf = nil
	return out
}

// readUntil reads until one of the markers appears, the budget runs out or
// the connection closes, and returns everything it read.
func (m *mgmtConn) readUntil(deadline time.Time, markers ...string) string {
	for {
		text := string(m.buf)
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimRight(line, "\r")
			upperLine := strings.ToUpper(line)
			for _, marker := range markers {
				if strings.HasPrefix(upperLine, strings.ToUpper(marker)) {
					m.buf = nil
					return text
				}
			}
		}
		if !time.Now().Before(deadline) {
			m.buf = nil
			return text
		}
		if err := m.fill(deadline); err != nil {
			m.buf = nil
			return text
		}
	}
}

// readPassword reads the management password: the first line of the file,
// trimmed. The second value reports whether the file was readable.
func readPassword(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	line := string(data)
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line), true
}

// mgmtHasCN reports whether the management status output still lists a
// CLIENT_LIST row for the common name.
//
// The match is exact: a common name containing a comma can never match, and
// that fails closed toward a timeout instead of a false "verified".
func mgmtHasCN(text, cn string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "CLIENT_LIST") {
			continue
		}
		delim := "\t"
		if !strings.Contains(line, "\t") {
			delim = ","
		}
		parts := strings.Split(line, delim)
		if len(parts) > 1 && parts[1] == cn {
			return true
		}
	}
	return false
}

// shorten collapses whitespace and cuts the text, the way the bash hook
// formatted its replies.
func shorten(s string, max int) string {
	flat := strings.Join(strings.Fields(s), " ")
	if len(flat) > max {
		return flat[:max]
	}
	return flat
}
