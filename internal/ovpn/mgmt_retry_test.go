// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"errors"
	"net"
	"testing"
	"time"
)

// The management interface serves one client at a time; a transient hold must
// not become a refused VPN client. One retry with a longer deadline, and the
// second attempt is the one whose timeout is used.
func TestDialManagementRetryOnceOnTransientFailure(t *testing.T) {
	prev := dialMgmt
	t.Cleanup(func() { dialMgmt = prev })

	var attempts []time.Duration
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	dialMgmt = func(_ int, timeout time.Duration) (net.Conn, error) {
		attempts = append(attempts, timeout)
		if len(attempts) == 1 {
			return nil, errors.New("dial tcp 127.0.0.1:7572: i/o timeout")
		}
		return client, nil
	}

	conn, err := dialManagementRetry(7572)
	if err != nil {
		t.Fatalf("retry returned %v, want the second attempt's connection", err)
	}
	_ = conn.Close()
	if len(attempts) != 2 {
		t.Fatalf("dial attempts = %d, want 2", len(attempts))
	}
	if attempts[0] != mgmtDialTimeout || attempts[1] != mgmtDialRetryTimeout {
		t.Fatalf("timeouts = %v, want [%v %v]", attempts, mgmtDialTimeout, mgmtDialRetryTimeout)
	}
}

// Two failures still surface the error: the retry is one extra chance, not a
// loop that holds the client handshake.
func TestDialManagementRetryGivesUpAfterOneRetry(t *testing.T) {
	prev := dialMgmt
	t.Cleanup(func() { dialMgmt = prev })

	attempts := 0
	dialMgmt = func(int, time.Duration) (net.Conn, error) {
		attempts++
		return nil, errors.New("connection refused")
	}
	if _, err := dialManagementRetry(7572); err == nil {
		t.Fatal("retry reported success with no connection")
	}
	if attempts != 2 {
		t.Fatalf("dial attempts = %d, want 2", attempts)
	}
}
