package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHookFromEnvValidatesRanges(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	t.Setenv("OVNODE_DATA_DIR", dir+"/ovnode-data")
	t.Setenv("OVNODE_MANAGEMENT_PORT", "0")
	t.Setenv("OVNODE_SESSION_TTL", "-5")
	cfg := HookFromEnv()
	if cfg.MgmtPort != DefaultMgmtPort {
		t.Fatalf("mgmt port = %d, want %d", cfg.MgmtPort, DefaultMgmtPort)
	}
	if cfg.SessionTTL != DefaultSessionTTL {
		t.Fatalf("session ttl = %d, want %d", cfg.SessionTTL, DefaultSessionTTL)
	}
	// event log should mention fallback
	data, _ := os.ReadFile(filepath.Join(cfg.LogDir, "hook-events.log"))
	if !contains(string(data), "invalid") {
		t.Fatalf("expected fallback log, got %q", string(data))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
