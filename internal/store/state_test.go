// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"os"
	"path/filepath"
	"testing"
)

// The panel's login limit and activation state live in one file per user,
// and the OpenVPN hook reads it on every handshake. A write that loses the
// other field would silently unblock a disabled user or reset a limit.
func TestWriteUserStateMergesFields(t *testing.T) {
	dir := t.TempDir()
	if err := SetLimit(dir, "alice", 3); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	if err := SetDisabled(dir, "alice", true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}
	st := ReadUserState(dir, "alice")
	if !st.LimitSet || st.Limit != 3 {
		t.Errorf("limit = %d (set=%v), want 3", st.Limit, st.LimitSet)
	}
	if !st.Disabled {
		t.Error("disabled = false, want true after SetDisabled")
	}

	// Setting the limit again must not re-enable the user.
	if err := SetLimit(dir, "alice", 5); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	st = ReadUserState(dir, "alice")
	if st.Limit != 5 {
		t.Errorf("limit = %d, want 5", st.Limit)
	}
	if !st.Disabled {
		t.Error("disabled = false, want true — a limit write cleared it")
	}
}

// limit=0 means unlimited, which is different from "no limit recorded".
func TestWriteUserStateKeepsUnlimitedDistinct(t *testing.T) {
	dir := t.TempDir()
	if err := SetLimit(dir, "bob", 0); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	st := ReadUserState(dir, "bob")
	if !st.LimitSet {
		t.Fatal("LimitSet = false, want true — limit=0 must be recorded")
	}
	if st.Limit != 0 {
		t.Errorf("limit = %d, want 0", st.Limit)
	}
}

// A state write must converge the tree: the legacy split files are removed
// once the merged file lands, so the hook cannot read a stale one. The
// legacy marker is still authoritative before the merge — it is the only
// record the node has — so it is carried into the merged file.
func TestWriteUserStateRemovesLegacyFiles(t *testing.T) {
	dir := t.TempDir()
	userDir := filepath.Join(dir, "carol")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDir, "limit"), []byte("9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDir, "disabled"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SetLimit(dir, "carol", 2); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	for _, name := range []string{"limit", "disabled"} {
		if _, err := os.Stat(filepath.Join(userDir, name)); !os.IsNotExist(err) {
			t.Errorf("legacy %s file still present", name)
		}
	}
	st := ReadUserState(dir, "carol")
	if st.Limit != 2 {
		t.Errorf("limit = %d, want 2", st.Limit)
	}
	if !st.Disabled {
		t.Error("disabled = false, want true — the legacy marker was lost in the merge")
	}

	// The merged file is authoritative from now on: an explicit
	// deactivation must survive a later limit write.
	if err := SetDisabled(dir, "carol", false); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}
	if err := SetLimit(dir, "carol", 4); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	if st = ReadUserState(dir, "carol"); st.Disabled {
		t.Error("disabled = true, want false — the merged file was overridden")
	}
}

// A CN that reaches the filesystem as a path component must be refused.
func TestWriteUserStateRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	if err := SetLimit(dir, "../escape", 1); err == nil {
		t.Fatal("SetLimit accepted a traversal CN")
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "escape")); err == nil {
		t.Fatal("a directory was created outside the users tree")
	}
}

func TestNameMapResolvesBothDirections(t *testing.T) {
	dir := t.TempDir()
	if err := CreateUser(dir, "dave"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := WriteName(dir, "dave", "dave@example"); err != nil {
		t.Fatalf("WriteName: %v", err)
	}
	InvalidateNameCache()
	m := NameMap(dir)
	if m["dave"] != "dave@example" {
		t.Errorf("NameMap[dave] = %q, want dave@example", m["dave"])
	}
	if got := CNForName(dir, "dave@example"); got != "dave" {
		t.Errorf("CNForName = %q, want dave", got)
	}
}

func TestAccumulatedUsageCountsOnlyDigits(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "eve"), []byte("1234\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "frank"), []byte("not-a-number"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := AccumulatedUsage(dir, "eve"); got != 1234 {
		t.Errorf("AccumulatedUsage(eve) = %d, want 1234", got)
	}
	if got := AccumulatedUsage(dir, "frank"); got != 0 {
		t.Errorf("AccumulatedUsage(frank) = %d, want 0 for a corrupt file", got)
	}
	if got := AccumulatedUsage(dir, "nobody"); got != 0 {
		t.Errorf("AccumulatedUsage(nobody) = %d, want 0 for a missing file", got)
	}
}

// The .lock.<cn> file is the store's own flock file, not a user.
func TestAllAccumulatedUsageSkipsLockFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gina"), []byte("10\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".lock.gina"), []byte("99\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	InvalidateUsageCache()
	m := AllAccumulatedUsage(dir)
	if m["gina"] != 10 {
		t.Errorf("AllAccumulatedUsage[gina] = %d, want 10", m["gina"])
	}
	if _, ok := m[".lock.gina"]; ok {
		t.Error("the lock file was counted as a user")
	}
}

// A reset must survive a concurrent disconnect hook writing the pre-reset
// total back, so the removal happens under the usage lock.
func TestResetUsageRemovesBankedBytes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hank"), []byte("500\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	InvalidateUsageCache()
	if err := ResetUsage(dir, "hank"); err != nil {
		t.Fatalf("ResetUsage: %v", err)
	}
	if got := AccumulatedUsage(dir, "hank"); got != 0 {
		t.Errorf("AccumulatedUsage(hank) = %d, want 0 after reset", got)
	}
}

// A deleted user must not leave its per-CN lock file behind: they pile up
// in the usage directory, one per user that ever existed.
func TestDeleteUserRemovesLockFiles(t *testing.T) {
	usersDir := t.TempDir()
	sessionsDir := t.TempDir()
	usageDir := t.TempDir()
	if err := CreateUser(usersDir, "ivan"); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{sessionsDir, usageDir} {
		if err := os.WriteFile(filepath.Join(dir, ".lock.ivan"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	DeleteUser(usersDir, sessionsDir, usageDir, "ivan")
	for _, dir := range []string{sessionsDir, usageDir} {
		if _, err := os.Stat(filepath.Join(dir, ".lock.ivan")); !os.IsNotExist(err) {
			t.Errorf("the lock file in %s survived the delete", dir)
		}
	}
}
