// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"net"
	"strings"
	"testing"
	"time"
)

// A limit=1 takeover queues the old client id and admits the new connection.
// It must not open the management slot or call kill <cn>.
func TestConnectLimitOneQueuesTakeover(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=0\n")
	writeOverflowStatus(t, tr,
		row("u1", "9.9.9.9:5002", "10.8.0.2", "100", "200", "42"),
	)
	setClientEnv(t, "u1", "10.8.0.11")
	commands := withKill(t)

	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect exit code = %d, want 0", code)
	}
	if len(*commands) != 1 || (*commands)[0] != "client-kill 42" {
		t.Fatalf("queued commands = %v, want client-kill 42", *commands)
	}
	if !hasEvent(tr.events(t), "TAKEOVER queued client-kill cid=42") {
		t.Fatalf("takeover not logged: %v", tr.events(t))
	}
}

func readLine(conn net.Conn) string {
	var b []byte
	buf := make([]byte, 1)
	deadline := time.Now().Add(2 * time.Second)
	for {
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if n > 0 {
			b = append(b, buf[:n]...)
			if strings.Contains(string(b), "\n") {
				return string(b)
			}
		}
		if err != nil {
			return string(b)
		}
	}
}
