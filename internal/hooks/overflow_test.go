// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const overflowHeader = "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID\n"

func writeOverflowStatus(t *testing.T, tr *tree, rows ...string) {
	t.Helper()
	body := overflowHeader + strings.Join(rows, "\n") + "\n"
	if err := os.WriteFile(tr.status, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// LiveSessionsForCN reads every protocol's status file; point all of them
	// at this fixture (the process env is consulted when .env has no key).
	t.Setenv("StatusFile", tr.status)
}

func row(cn, real, virtual, recv, sent, cid string) string {
	return "CLIENT_LIST," + cn + "," + real + "," + virtual + ",," + recv + "," + sent +
		",2026-01-01 00:00:00,1767225600,," + cid + ",0"
}

// startMgmt answers the takeover dialogue: banner+password, then one command
// (kill <cn>), then a status read that returns END (no client left).
func startMgmt(t *testing.T, tr *tree) int {
	t.Helper()
	passFile := filepath.Join(tr.dir, "mgmt-pass")
	if err := os.WriteFile(passFile, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("OpenVPN Management Interface\nENTER PASSWORD:"))
		readLine(conn)
		_, _ = conn.Write([]byte("SUCCESS: password ok\n"))
		readLine(conn)
		_, _ = conn.Write([]byte("SUCCESS: client killed\n"))
		readLine(conn)
		_, _ = conn.Write([]byte("END\n"))
		time.Sleep(100 * time.Millisecond)
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func hasEvent(events []string, substr string) bool {
	for _, line := range events {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

// limit=2 with two existing rows: the third (reconnect) is admitted via the
// +1 reserve instead of AUTH_FAILED.
func TestConnectOverflowReserveAllowsThirdSession(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=2\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "1.1.1.1:1000", "10.8.0.3", "100", "200", "41"),
		row("u1", "2.2.2.2:2000", "10.8.0.4", "100", "200", "42"),
	)
	setClientEnv(t, "u1", "10.8.0.2")

	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect = %d, want 0 (overflow reserve)", code)
	}
	if !hasEvent(tr.events(t), "ALLOW (overflow reserve +1)") {
		t.Fatalf("reserve admission not logged: %v", tr.events(t))
	}
}

// limit=2 with three failed (zero-byte) rows: the hard cap reclaims the CN
// (the only kill DCO supports) and admits.
func TestConnectOverflowCapReclaimsZeroByteRows(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=2\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "1.1.1.1:1000", "10.8.0.3", "0", "0", "41"),
		row("u1", "2.2.2.2:2000", "10.8.0.4", "0", "0", "42"),
		row("u1", "3.3.3.3:3000", "10.8.0.5", "0", "0", "43"),
	)
	setClientEnv(t, "u1", "10.8.0.2")

	cfg := tr.config()
	cfg.MgmtPort = startMgmt(t, tr)
	cfg.MgmtPassFile = filepath.Join(tr.dir, "mgmt-pass")

	if code := Connect(cfg, ""); code != 0 {
		t.Fatalf("Connect = %d, want 0 (reclaimed)", code)
	}
	if !hasEvent(tr.events(t), "RECLAIM kill-cn") {
		t.Fatalf("reclaim not logged: %v", tr.events(t))
	}
}

// limit=2 with three live rows on different IPs: never kick; refuse the 4th.
func TestConnectOverflowCapRefusesLiveSessions(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=2\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "1.1.1.1:1000", "10.8.0.3", "100", "200", "41"),
		row("u1", "2.2.2.2:2000", "10.8.0.4", "100", "200", "42"),
		row("u1", "3.3.3.3:3000", "10.8.0.5", "100", "200", "43"),
	)
	setClientEnv(t, "u1", "10.8.0.2")

	if code := Connect(tr.config(), ""); code != 1 {
		t.Fatalf("Connect = %d, want 1 (overflow cap, live sessions)", code)
	}
	if !hasEvent(tr.events(t), "REJECT (overflow cap, live sessions)") {
		t.Fatalf("cap refusal not logged: %v", tr.events(t))
	}
}

// Three rows on one IP with real usage are real devices behind one NAT: the
// hard cap refuses instead of killing all of them.
func TestConnectOverflowCapRefusesSameIPDevices(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=2\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "9.9.9.9:5002", "10.8.0.3", "100", "200", "41"),
		row("u1", "9.9.9.9:5003", "10.8.0.4", "100", "200", "42"),
		row("u1", "9.9.9.9:5004", "10.8.0.5", "100", "200", "43"),
	)
	setClientEnv(t, "u1", "10.8.0.2")

	if code := Connect(tr.config(), ""); code != 1 {
		t.Fatalf("Connect = %d, want 1 (same-NAT devices are live)", code)
	}
	if !hasEvent(tr.events(t), "REJECT (overflow cap, live sessions)") {
		t.Fatalf("cap refusal not logged: %v", tr.events(t))
	}
}
