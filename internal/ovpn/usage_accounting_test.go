// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"path/filepath"
	"testing"

	"ovnode/internal/fsx"
	"ovnode/internal/pki"
	"ovnode/internal/store"
)

func accountingTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("OVN_APP_DIR", filepath.Join(root, "app"))
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	t.Setenv("OVNODE_DATA_DIR", filepath.Join(root, "data"))
	t.Setenv("OVNODE_USERS_DIR", filepath.Join(root, "data", "users"))
	t.Setenv("OVNODE_SESSIONS_DIR", filepath.Join(root, "data", "sessions"))
	t.Setenv("OVNODE_USAGE_DIR", filepath.Join(root, "data", "usage"))
	t.Setenv("OVNODE_LOG_FILE", filepath.Join(root, "events.log"))
	if err := os.MkdirAll(filepath.Join(root, "server"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{pki.UsersDir(), pki.SessionsDir(), pki.UsageDir()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func accountingStatus(t *testing.T, rows string) {
	t.Helper()
	body := "TIME\tfixture\t150\n" +
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\n" +
		rows + "END\n"
	if err := os.WriteFile(StatusFile(), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestStaleSnapshotDoesNotChargeReplacementSession: a status snapshot that
// predates the replacement marker must not be assigned to the new
// generation (A=150 closed + stale A=100 + B=20 totals 170, not 250).
func TestStaleSnapshotDoesNotChargeReplacementSession(t *testing.T) {
	accountingTree(t)
	if _, err := store.RecordSessionUsage(pki.UsageDir(), "alice", "alice.10.66.0.2.A", 150, true); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteMarker(filepath.Join(pki.SessionsDir(), "alice.10.66.0.2"), store.Marker{
		CommonName: "alice", PoolIP: "10.66.0.2", TrustedIP: "198.51.100.2", TrustedPort: "2000",
		Created: 200, ConnectedAt: 200, SessionID: "alice.10.66.0.2.B",
	}); err != nil {
		t.Fatal(err)
	}
	accountingStatus(t, "CLIENT_LIST\talice\t198.51.100.1:1000\t10.66.0.2\t\t100\t0\tfixture\t100\tUNDEF\t1\n")
	if _, err := UsersUsage(); err != nil {
		t.Fatal(err)
	}
	state, err := store.RecordSessionUsage(pki.UsageDir(), "alice", "alice.10.66.0.2.B", 20, true)
	if err != nil {
		t.Fatal(err)
	}
	if state.Total != 170 {
		t.Fatalf("stale A snapshot was assigned to replacement B: persisted total=%d, want 150+20=170", state.Total)
	}
}

// TestCompletedDottedCNAppearsInTotals: a completed dotted CN (alice.vpn)
// is not dropped by the totals enumeration namespace.
func TestCompletedDottedCNAppearsInTotals(t *testing.T) {
	accountingTree(t)
	if _, err := store.RecordSessionUsage(pki.UsageDir(), "alice.vpn", "completed-session", 50, true); err != nil {
		t.Fatal(err)
	}
	accountingStatus(t, "")
	usage, err := UsersUsage()
	if err != nil {
		t.Fatal(err)
	}
	totals := usage["totals"].(map[string]uint64)
	if total, exists := totals["alice.vpn"]; !exists || total != 50 {
		t.Fatalf("valid completed dotted CN omitted from totals: exists=%v total=%d, want 50", exists, total)
	}
	epochs := usage["totals_epochs"].(map[string]string)
	if _, exists := epochs["alice.vpn"]; !exists {
		t.Fatal("totals_epochs missing the dotted CN contributor")
	}
}

// TestCorruptCounterIsUnavailableNotPartialSuccess: one corrupt persisted
// counter fails the whole usage sample instead of reporting partial data.
func TestCorruptCounterIsUnavailableNotPartialSuccess(t *testing.T) {
	accountingTree(t)
	if err := os.WriteFile(filepath.Join(pki.UsageDir(), "alice"), []byte("corrupt counter"), 0o644); err != nil {
		t.Fatal(err)
	}
	accountingStatus(t, "")
	if _, err := UsersUsage(); err == nil {
		t.Fatal("corrupt persisted counter reported as successful sample")
	}
}

// TestMarkerlessLiveSessionContinuesUsage: a live session with no marker
// (pre-upgrade) still accounts, keyed by its observed status identity.
func TestMarkerlessLiveSessionContinuesUsage(t *testing.T) {
	accountingTree(t)
	accountingStatus(t, "CLIENT_LIST\talice\t198.51.100.1:1000\t10.66.0.2\t\t50\t0\tfixture\t100\tUNDEF\t1\n")
	usage, err := UsersUsage()
	if err != nil {
		t.Fatal(err)
	}
	totals := usage["totals"].(map[string]uint64)
	if total := totals["alice"]; total != 50 {
		t.Fatalf("active markerless pre-upgrade session lost from total: got %d, want 50", total)
	}
	// A second poll of the same session must not double-count.
	accountingStatus(t, "CLIENT_LIST\talice\t198.51.100.1:1000\t10.66.0.2\t\t70\t0\tfixture\t100\tUNDEF\t1\n")
	usage, err = UsersUsage()
	if err != nil {
		t.Fatal(err)
	}
	totals = usage["totals"].(map[string]uint64)
	if total := totals["alice"]; total != 70 {
		t.Fatalf("markerless session double-counted across polls: got %d, want 70", total)
	}
}

// TestIncompleteStatusSnapshotIsRejected: a status file without END (or
// unreadable) makes the usage sample unavailable.
func TestIncompleteStatusSnapshotIsRejected(t *testing.T) {
	accountingTree(t)
	body := "TIME\tfixture\t150\nCLIENT_LIST\talice\t198.51.100.1:1000\t10.66.0.2\t\t50\t0\tfixture\t100\tUNDEF\t1\n"
	if err := os.WriteFile(StatusFile(), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := UsersUsage(); err == nil {
		t.Fatal("incomplete status snapshot reported as successful sample")
	}
	_ = fsx.StatusFile()
}
