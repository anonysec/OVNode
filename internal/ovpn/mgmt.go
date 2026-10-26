// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"fmt"
	"net"
	"os"
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
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, mgmtDialTimeout)
	if err != nil {
		return TakeoverDown, []string{fmt.Sprintf("RESULT DOWN (%s)", err)}
	}
	defer conn.Close()
	m := &mgmtConn{conn: conn}

	if strings.Contains(strings.ToUpper(m.readBanner()), "PASSWORD") {
		if pw, ok := readPassword(passFile); ok {
			_ = conn.SetWriteDeadline(time.Now().Add(mgmtReplyBudget))
			if _, err := conn.Write([]byte(pw + "\n")); err == nil {
				// The interface answers the password; a real one that
				// does not must not stall the takeover.
				m.readUntil(time.Now().Add(mgmtAuthBudget), "SUCCESS", "ERROR")
			}
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
	if v := os.Getenv("OVNODE_MANAGEMENT_HOST"); v != "" {
		return v
	}
	if v := os.Getenv("OVNODE_MGMT_HOST"); v != "" {
		return v
	}
	return "127.0.0.1"
}

// dialManagement opens a connection to the management socket.
func dialManagement() (net.Conn, error) {
	addr := net.JoinHostPort(mgmtHost(), strconv.Itoa(ManagementPort()))
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
	conn, err := dialManagement()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	m := &mgmtConn{conn: conn}

	if strings.Contains(strings.ToUpper(m.readBanner()), "PASSWORD") {
		if pw, ok := readPassword(pki.MgmtPassFile()); ok {
			_ = conn.SetWriteDeadline(time.Now().Add(mgmtReplyBudget))
			if _, err := conn.Write([]byte(pw + "\n")); err == nil {
				m.readUntil(time.Now().Add(mgmtAuthBudget), "SUCCESS", "ERROR")
			}
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
		upper := strings.ToUpper(text)
		for _, marker := range markers {
			if strings.Contains(upper, marker) {
				m.buf = nil
				return text
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
		if !strings.HasPrefix(line, "CLIENT_LIST,") {
			continue
		}
		parts := strings.Split(line, ",")
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
