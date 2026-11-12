// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMgmtSessionsTabSeparated(t *testing.T) {
	text := "TITLE\tOpenVPN 2.7.0\n" +
		"TIME\t2026-11-12 08:49:00\t1794473340\n" +
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\n" +
		"CLIENT_LIST\t2\tudp4:37.63.172.130:44232\t10.66.0.2\t\t66492876\t262081268\t2026-11-12 08:45:30\t1794473130\tUNDEF\t1\t0\tAES-128-GCM\n" +
		"CLIENT_LIST\t2\tudp4:37.63.172.130:55571\t10.66.0.3\t\t204299\t527257\t2026-11-12 08:45:44\t1794473144\tUNDEF\t2\t1\tAES-128-GCM\n" +
		"END\n"
	got := parseMgmtSessions(text, "2")
	if len(got) != 2 {
		t.Fatalf("sessions = %d, want 2", len(got))
	}
	if got[0].VirtualAddress != "10.66.0.2" || got[0].ClientID != "1" {
		t.Fatalf("first session = %+v", got[0])
	}
	if got[1].VirtualAddress != "10.66.0.3" || got[1].ClientID != "2" {
		t.Fatalf("second session = %+v", got[1])
	}
}

func TestLiveSessionsFallsBackToStatusFiles(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OpenVpnRoot", root)
	t.Setenv("DataDir", root)
	t.Setenv("ManagementPort", "1") // nothing listens there
	status := filepath.Join(root, "server", "udp", "status.log")
	if err := os.MkdirAll(filepath.Dir(status), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\n" +
		"CLIENT_LIST\t2\tudp4:37.63.172.130:44232\t10.66.0.2\t\t1\t2\t2026-11-12 08:45:30\t1794473130\tUNDEF\t1\t0\tAES-128-GCM\n" +
		"HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)\nEND\n"
	if err := os.WriteFile(status, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := LiveSessionsForCN(status, "2")
	if len(got) != 1 || got[0].VirtualAddress != "10.66.0.2" {
		t.Fatalf("sessions = %+v", got)
	}
}

func TestMgmtHasCNHandlesTabAndComma(t *testing.T) {
	tab := "CLIENT_LIST\t2\tudp4:37.63.172.130:44232\t10.66.0.2\t\t1\t2\t2026-11-12 08:45:30\t1794473130\tUNDEF\t1\t0\tAES-128-GCM\n"
	if !mgmtHasCN(tab, "2") {
		t.Fatal("tab-separated CLIENT_LIST not recognized")
	}
	comma := "CLIENT_LIST,2,udp4:37.63.172.130:44232,10.66.0.2,,1,2,2026-11-12 08:45:30,1794473130,UNDEF,1,0,AES-128-GCM\n"
	if !mgmtHasCN(comma, "2") {
		t.Fatal("comma-separated CLIENT_LIST not recognized")
	}
	if mgmtHasCN(tab, "3") {
		t.Fatal("wrong CN matched")
	}
}
