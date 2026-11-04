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

func TestConnectTakeoverWithFakeManagementSocket(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=0\n")

	status := "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID\n" +
		"CLIENT_LIST,u1,9.9.9.9:5001,10.8.0.2,,,,0,0,,,,42,0\n"
	if err := os.WriteFile(tr.status, []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}

	setClientEnv(t, "u1", "10.8.0.2")

	passFile := filepath.Join(tr.dir, "mgmt-pass")
	if err := os.WriteFile(passFile, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

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

	cfg := tr.config()
	cfg.MgmtPort = port
	cfg.MgmtPassFile = passFile

	if code := Connect(cfg, ""); code != 0 {
		t.Fatalf("Connect exit code = %d, want 0", code)
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
