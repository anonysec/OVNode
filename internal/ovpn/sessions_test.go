// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestUserDiagnosticsCountsLiveSessionsAndStaleMarkers covers the counters
// the panel reads.
//
// A marker is live when its (common name, pool IP) pair is in the status
// file: the pool IP survives a reconnect, the real address does not.
func TestUserDiagnosticsCountsLiveSessionsAndStaleMarkers(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	t.Setenv("OVNODE_LOG_FILE", filepath.Join(root, "hook-events.log"))
	sessionsDir := filepath.Join(root, "ovnode", "sessions")
	if err := os.MkdirAll(sessionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := filepath.Join(root, "server", "status.log")
	if err := os.MkdirAll(filepath.Dir(status), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\t" +
		"Bytes Received\tBytes Sent\tClient ID\n" +
		"CLIENT_LIST\tlive-user\t5.5.5.5:4000\t10.8.0.2\t100\t200\t7\n"
	if err := os.WriteFile(status, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// A live marker and a stale one.
	live := "common_name=live-user\ntrusted_ip=5.5.5.5\ntrusted_port=4000\n" +
		"ifconfig_pool_remote_ip=10.8.0.2\ncreated=1000\n"
	stale := "common_name=dead-user\ntrusted_ip=6.6.6.6\ntrusted_port=4001\n" +
		"ifconfig_pool_remote_ip=10.8.0.9\ncreated=1000\n"
	if err := os.WriteFile(filepath.Join(sessionsDir, "live-user.10.8.0.2"), []byte(live), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionsDir, "dead-user.10.8.0.9"), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}

	data := UserDiagnostics("", 8)
	if got := data["live_count"].(int); got != 1 {
		t.Fatalf("live_count = %d, want 1", got)
	}
	if got := data["stale_marker_count"].(int); got != 1 {
		t.Fatalf("stale_marker_count = %d, want 1", got)
	}
	staleMarkers, _ := data["stale_markers"].([]map[string]any)
	if len(staleMarkers) != 1 {
		t.Fatalf("stale_markers = %v, want one entry", data["stale_markers"])
	}
	if staleMarkers[0]["common_name"] != "dead-user" {
		t.Fatalf("the stale marker is %v, want the dead user", staleMarkers[0])
	}
	liveSessions, _ := data["live_sessions"].([]map[string]any)
	if len(liveSessions) != 1 {
		t.Fatalf("live_sessions = %v, want one entry", data["live_sessions"])
	}
	if liveSessions[0]["common_name"] != "live-user" {
		t.Fatalf("the live session is %v, want the live user", liveSessions[0])
	}
}

// TestUserDiagnosticsClassifiesHookEvents covers the counters the panel's
// security view reads.
func TestUserDiagnosticsClassifiesHookEvents(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	logFile := filepath.Join(root, "hook-events.log")
	t.Setenv("OVNODE_LOG_FILE", logFile)
	if err := os.MkdirAll(filepath.Join(root, "ovnode", "sessions"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := nowEpoch()
	body := ""
	body += epochLine(now, "CN=7 ip=1.2.3.4:5678; USERS_DIR missing; REJECT")
	body += epochLine(now, "CN=8 ip=1.2.3.4:5679 is disabled; REJECT")
	body += epochLine(now, "CN=9 ip=1.2.3.4:5680 pool=10.8.0.3 limit=2 status=2; REJECT")
	if err := os.WriteFile(logFile, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	data := UserDiagnostics("", 8)
	if got := data["rejects"].(int); got != 3 {
		t.Fatalf("rejects = %d, want 3", got)
	}
	if got := data["policy_rejects"].(int); got != 2 {
		t.Fatalf("policy_rejects = %d, want 2", got)
	}
	if got := data["failures"].(int); got != 1 {
		t.Fatalf("failures = %d, want 1", got)
	}
	if got := data["auth_errors"].(int); got != 1 {
		t.Fatalf("auth_errors = %d, want 1", got)
	}
	byCN, _ := data["auth_errors_by_cn"].(map[string]int)
	if byCN["7"] != 1 {
		t.Fatalf("auth_errors_by_cn = %v, want one failure for the user 7", byCN)
	}
	events, _ := data["events"].([]Event)
	found := false
	for _, ev := range events {
		if ev.CN == "7" {
			found = true
			if ev.Severity != SeverityFailure {
				t.Fatalf("the event severity is %q, want %q", ev.Severity, SeverityFailure)
			}
		}
	}
	if !found {
		t.Fatalf("the events %v carry no entry for the user 7", events)
	}
}

// TestUserDiagnosticsMapsTheCNToTheDisplayName covers the username lookup.
//
// The panel reads the auth counts up by the panel USERNAME, so the node
// maps the common names before it answers.
func TestUserDiagnosticsMapsTheCNToTheDisplayName(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	logFile := filepath.Join(root, "hook-events.log")
	t.Setenv("OVNODE_LOG_FILE", logFile)
	userDir := filepath.Join(root, "ovnode", "users", "42")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDir, "name"), []byte("alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := nowEpoch()
	body := epochLine(now, "CN=42 ip=1.2.3.4:5678; USERS_DIR missing; REJECT")
	if err := os.WriteFile(logFile, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	data := UserDiagnostics("", 8)
	byCN, _ := data["auth_errors_by_cn"].(map[string]int)
	if byCN["alice"] != 1 {
		t.Fatalf("auth_errors_by_cn = %v, want the failure under the display name", byCN)
	}
}

// nowEpoch returns the current epoch second.
func nowEpoch() int64 { return time.Now().Unix() }

// epochLine builds one hook event line.
func epochLine(ts int64, message string) string {
	return fmt.Sprintf("%d [ovnode-mlogin] %s\n", ts, message)
}
