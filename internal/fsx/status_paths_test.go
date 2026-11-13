// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package fsx

import "testing"

// The per-protocol status paths must differ when no single-file override is
// set; the hook reads both to enforce one limit across transports.
func TestStatusFileIsPerProtocol(t *testing.T) {
	t.Setenv("StatusFile", "")
	udp := StatusFile("udp")
	tcp := StatusFile("tcp")
	if udp == tcp {
		t.Fatalf("udp and tcp status files are both %q", udp)
	}
}
