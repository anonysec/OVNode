// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ovnode/internal/config"
)

// tree is a hermetic node tree: users, sessions, usage and the event log.
type tree struct {
	dir      string
	users    string
	sessions string
	usage    string
	status   string
	logFile  string
}

func newTree(t *testing.T) *tree {
	t.Helper()
	dir := t.TempDir()
	tr := &tree{
		dir:      dir,
		users:    filepath.Join(dir, "users"),
		sessions: filepath.Join(dir, "sessions"),
		usage:    filepath.Join(dir, "usage"),
		status:   filepath.Join(dir, "status.log"),
		logFile:  filepath.Join(dir, "log", "hook-events.log"),
	}
	for _, d := range []string{tr.users, tr.sessions, tr.usage} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(tr.status, []byte("HEADER\tX\n"), 0o644); err != nil {
		t.Fatalf("write status: %v", err)
	}
	return tr
}

func (tr *tree) config() config.Hook {
	return config.Hook{
		UsersDir:     tr.users,
		SessionsDir:  tr.sessions,
		UsageDir:     tr.usage,
		StatusFile:   tr.status,
		LogFile:      tr.logFile,
		MgmtHost:     "127.0.0.1",
		MgmtPort:     1,
		MgmtPassFile: filepath.Join(tr.dir, "mgmt-pass"),
		SessionTTL:   86400,
	}
}

func (tr *tree) user(t *testing.T, cn, state string) {
	t.Helper()
	dir := filepath.Join(tr.users, cn)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir user: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state"), []byte(state), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}
}

func (tr *tree) events(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(tr.logFile)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		// Strip the "<epoch> [tag] " prefix: the timestamp moves.
		if i := strings.Index(line, " "); i >= 0 {
			line = line[i+1:]
		}
		out = append(out, line)
	}
	return out
}

func setClientEnv(t *testing.T, cn, pool string) {
	t.Helper()
	t.Setenv("common_name", cn)
	t.Setenv("trusted_ip", "9.9.9.9")
	t.Setenv("trusted_port", "5001")
	t.Setenv("ifconfig_pool_remote_ip", pool)
	t.Setenv("bytes_received", "")
	t.Setenv("bytes_sent", "")
}

// TestConnectWritesTheGoldenMarker pins the marker the panel and the purge
// read: the field names and their order are the on-disk contract.
func TestConnectWritesTheGoldenMarker(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=0\n")
	setClientEnv(t, "u1", "10.8.0.2")

	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect exit code = %d, want 0", code)
	}

	marker := filepath.Join(tr.sessions, "u1.10.8.0.2")
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("marker missing: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	want := []string{
		"common_name=u1",
		"trusted_ip=9.9.9.9",
		"trusted_port=5001",
		"ifconfig_pool_remote_ip=10.8.0.2",
	}
	for i, w := range want {
		if i >= len(lines) || lines[i] != w {
			t.Fatalf("marker line %d = %q, want %q (marker: %q)", i, lines[i], w, string(data))
		}
	}
	if len(lines) != 5 || !strings.HasPrefix(lines[4], "created=") {
		t.Fatalf("marker = %q, want a created= line last", string(data))
	}
	info, err := os.Stat(marker)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("marker mode = %o, want 600", perm)
	}
}

// TestConnectLogsTheGoldenAllowLine pins the event line the panel
// classifies. The wording is the API.
func TestConnectLogsTheGoldenAllowLine(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=0\n")
	setClientEnv(t, "u1", "10.8.0.2")

	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect exit code = %d, want 0", code)
	}
	events := tr.events(t)
	if len(events) != 1 {
		t.Fatalf("events = %v, want one line", events)
	}
	want := "[ovnode-mlogin] CN=u1 ip=9.9.9.9:5001 pool=10.8.0.2 limit=1 status=0; ALLOW session=u1.10.8.0.2"
	if events[0] != want {
		t.Fatalf("event = %q, want %q", events[0], want)
	}
}

// TestConnectRefusesDisabledUser keeps the "is disabled" token: the panel
// classifies the line as a policy reject, not an auth failure.
func TestConnectRefusesDisabledUser(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=1\ndisabled=1\n")
	setClientEnv(t, "u1", "10.8.0.2")

	if code := Connect(tr.config(), ""); code != 1 {
		t.Fatalf("Connect exit code = %d, want 1", code)
	}
	events := tr.events(t)
	if len(events) != 1 || !strings.Contains(events[0], "is disabled; REJECT") {
		t.Fatalf("events = %v, want the disabled reject", events)
	}
	entries, _ := os.ReadDir(tr.sessions)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("marker %q written for a disabled user", e.Name())
		}
	}
}

// TestConnectFailsClosedWithoutUsersDir keeps the "USERS_DIR missing"
// token: the panel shows it as a node failure, not a user problem.
func TestConnectFailsClosedWithoutUsersDir(t *testing.T) {
	tr := newTree(t)
	setClientEnv(t, "u1", "10.8.0.2")
	cfg := tr.config()
	cfg.UsersDir = filepath.Join(tr.dir, "does-not-exist")

	if code := Connect(cfg, ""); code != 1 {
		t.Fatalf("Connect exit code = %d, want 1", code)
	}
	events := tr.events(t)
	if len(events) != 1 || !strings.Contains(events[0], "USERS_DIR missing") {
		t.Fatalf("events = %v, want the fail-closed line", events)
	}
}

// TestConnectRejectsMalformedCN keeps the hook failing closed on a name it
// cannot map to a file.
func TestConnectRejectsMalformedCN(t *testing.T) {
	tr := newTree(t)
	setClientEnv(t, "u1", "10.8.0.2")
	t.Setenv("common_name", "-flag")

	if code := Connect(tr.config(), ""); code != 1 {
		t.Fatalf("Connect exit code = %d, want 1", code)
	}
	events := tr.events(t)
	if len(events) != 1 || !strings.Contains(events[0], "rejected: malformed; REJECT") {
		t.Fatalf("events = %v, want the malformed reject", events)
	}
}

// TestConnectUnlimitedAllows keeps limit=0 out of the enforcement path.
func TestConnectUnlimitedAllows(t *testing.T) {
	tr := newTree(t)
	tr.user(t, "u1", "limit=0\ndisabled=0\n")
	setClientEnv(t, "u1", "10.8.0.2")

	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect exit code = %d, want 0", code)
	}
	events := tr.events(t)
	if len(events) != 1 || !strings.Contains(events[0], "limit=unlimited; LOCAL_ALLOW") {
		t.Fatalf("events = %v, want the unlimited line", events)
	}
}

// TestDisconnectBanksUsage pins the accumulator: the bytes of two finished
// sessions add up, and the marker is gone.
func TestDisconnectBanksUsage(t *testing.T) {
	tr := newTree(t)
	setClientEnv(t, "u1", "10.8.0.5")
	if code := Connect(tr.config(), ""); code != 0 {
		t.Fatalf("Connect exit code = %d, want 0", code)
	}
	for _, pair := range [][2]string{{"100", "50"}, {"7", "3"}} {
		t.Setenv("bytes_received", pair[0])
		t.Setenv("bytes_sent", pair[1])
		if code := Disconnect(tr.config(), ""); code != 0 {
			t.Fatalf("Disconnect exit code = %d, want 0", code)
		}
	}
	data, err := os.ReadFile(filepath.Join(tr.usage, "u1"))
	if err != nil {
		t.Fatalf("usage file missing: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "160" {
		t.Fatalf("usage = %q, want 160", got)
	}
	if _, err := os.Stat(filepath.Join(tr.sessions, "u1.10.8.0.5")); !os.IsNotExist(err) {
		t.Fatalf("marker survived the disconnect")
	}
}

// TestPurgeRemovesOnlyStaleDeadMarkers keeps the purge narrow: a fresh
// marker and a marker whose pool is still live stay.
func TestPurgeRemovesOnlyStaleDeadMarkers(t *testing.T) {
	tr := newTree(t)
	now := time.Now().Unix()
	old := now - 25*3600
	writeMarker := func(name, cn, pool string, created int64) {
		body := "common_name=" + cn + "\ntrusted_ip=5.5.5.5\ntrusted_port=4000\n" +
			"ifconfig_pool_remote_ip=" + pool + "\ncreated=" + strconv.FormatInt(created, 10) + "\n"
		if err := os.WriteFile(filepath.Join(tr.sessions, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeMarker("u1.10.8.0.1", "u1", "10.8.0.1", now)
	writeMarker("u2.10.8.0.2", "u2", "10.8.0.2", old)
	writeMarker("u3.10.8.0.3", "u3", "10.8.0.3", old)
	live := "CLIENT_LIST\tu3\t5.5.5.5:4000\t10.8.0.3\t10\t20\tnow\t1700000000\tu3\t\t9\n"
	if err := os.WriteFile(tr.status, []byte("HEADER\tX\n"+live), 0o644); err != nil {
		t.Fatal(err)
	}

	if code := PurgeStale(tr.config()); code != 0 {
		t.Fatalf("PurgeStale exit code = %d, want 0", code)
	}
	if _, err := os.Stat(filepath.Join(tr.sessions, "u2.10.8.0.2")); !os.IsNotExist(err) {
		t.Fatal("the stale marker with a dead pool survived")
	}
	if _, err := os.Stat(filepath.Join(tr.sessions, "u1.10.8.0.1")); err != nil {
		t.Fatal("the fresh marker was removed")
	}
	if _, err := os.Stat(filepath.Join(tr.sessions, "u3.10.8.0.3")); err != nil {
		t.Fatal("the marker with a live pool was removed")
	}
}
