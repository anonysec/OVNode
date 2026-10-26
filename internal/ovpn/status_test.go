// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseSessionsResolvesColumnsFromTheHeader covers the OpenVPN 2.7
// layout: the Virtual IPv6 column shifts every later field, so the columns
// must come from the HEADER line and not from fixed positions.
func TestParseSessionsResolvesColumnsFromTheHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.log")
	header := "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\t" +
		"Virtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\t" +
		"Connected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\n"
	row := "CLIENT_LIST\tu1\t5.5.5.5:4000\t10.8.0.2\t\t100\t200\tnow\t1700000000\t\t7\t\t\n"
	if err := os.WriteFile(path, []byte(header+row), 0o644); err != nil {
		t.Fatal(err)
	}

	sessions := ParseSessions(path)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	s := sessions[0]
	if s.CommonName != "u1" || s.VirtualAddress != "10.8.0.2" || s.ClientID != "7" {
		t.Fatalf("session = %+v, want u1 / 10.8.0.2 / cid 7", s)
	}
	if s.TrustedIP != "5.5.5.5" || s.TrustedPort != "4000" {
		t.Fatalf("real address split = %q:%q, want 5.5.5.5:4000", s.TrustedIP, s.TrustedPort)
	}
	if s.BytesReceived != 100 || s.BytesSent != 200 {
		t.Fatalf("bytes = %d/%d, want 100/200", s.BytesReceived, s.BytesSent)
	}
}

// TestParseSessionsFallsBackToTheDefaultColumns covers a status file
// without a HEADER line: the OpenVPN >= 2.4 positions are assumed.
func TestParseSessionsFallsBackToTheDefaultColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.log")
	row := "CLIENT_LIST\tu1\t5.5.5.5:4000\t10.8.0.2\t10\t20\tnow\t1700000000\tu1\t\t7\n"
	if err := os.WriteFile(path, []byte(row), 0o644); err != nil {
		t.Fatal(err)
	}
	sessions := ParseSessions(path)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	if sessions[0].CommonName != "u1" || sessions[0].ClientID != "7" {
		t.Fatalf("session = %+v, want u1 / cid 7", sessions[0])
	}
}

// TestParseSessionsReadsCommaDelimitedFiles covers the older comma layout.
func TestParseSessionsReadsCommaDelimitedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.log")
	body := "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Bytes Received,Bytes Sent,Connected Since,Updated At,Client ID\n" +
		"CLIENT_LIST,u1,5.5.5.5:4000,10.8.0.2,100,200,now,now,7\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sessions := ParseSessions(path)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	if sessions[0].CommonName != "u1" || sessions[0].VirtualAddress != "10.8.0.2" {
		t.Fatalf("session = %+v, want u1 / 10.8.0.2", sessions[0])
	}
}
