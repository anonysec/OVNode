package ovpn

import (
	"strings"
	"testing"
	"time"
)

func TestValidateMgmtHost(t *testing.T) {
	t.Setenv("OVNODE_ALLOW_REMOTE_MGMT", "")
	if err := validateMgmtHost("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := validateMgmtHost("8.8.8.8"); err == nil {
		t.Fatal("expected refusal")
	}
	t.Setenv("OVNODE_ALLOW_REMOTE_MGMT", "1")
	if err := validateMgmtHost("8.8.8.8"); err != nil {
		t.Fatal(err)
	}
}

func TestMgmtReadUntilLineStart(t *testing.T) {
	// marker at line start matches
	m := &mgmtConn{buf: []byte("SUCCESS: ok\n")}
	got := m.readUntil(time.Now().Add(time.Second), "SUCCESS")
	if !strings.Contains(got, "SUCCESS: ok") {
		t.Fatalf("got %q", got)
	}
	// marker only in middle of a line does not match; read returns without false positive
	m2 := &mgmtConn{buf: []byte("prefix SUCCESS suffix\n")}
	got2 := m2.readUntil(time.Now().Add(-time.Second), "SUCCESS")
	if strings.HasPrefix(strings.TrimSpace(got2), "SUCCESS") {
		t.Fatalf("false positive: %q", got2)
	}
}
