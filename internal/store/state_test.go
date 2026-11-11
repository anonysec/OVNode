// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"fmt"
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
	st, err := ReadUserState(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
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
	st, err = ReadUserState(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
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
	st, err := ReadUserState(dir, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if !st.LimitSet {
		t.Fatal("LimitSet = false, want true — limit=0 must be recorded")
	}
	if st.Limit != 0 {
		t.Errorf("limit = %d, want 0", st.Limit)
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

func TestWriteNamePreservesUnspecifiedPolicy(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"Alice = 阿丽丝", "", "Alice"} {
		if err := WriteName(dir, "alice", name); err != nil {
			t.Fatal(err)
		}
		st, err := ReadUserState(dir, "alice")
		if err != nil || st.LimitSet || st.Disabled || ReadName(dir, "alice") != name {
			t.Fatalf("name-only write changed unspecified policy: %+v (%v)", st, err)
		}
	}
	if err := SetLimit(dir, "alice", 0); err != nil {
		t.Fatal(err)
	}
	if err := SetDisabled(dir, "alice", true); err != nil {
		t.Fatal(err)
	}
	if err := WriteName(dir, "alice", "Bob"); err != nil {
		t.Fatal(err)
	}
	st, err := ReadUserState(dir, "alice")
	if err != nil || !st.LimitSet || st.Limit != 0 || !st.Disabled || ReadName(dir, "alice") != "Bob" {
		t.Fatalf("name-only write changed existing policy: %+v (%v)", st, err)
	}
}

func writeCounter(t *testing.T, dir, cn string, total uint64) {
	t.Helper()
	body := fmt.Sprintf(`{"version":2,"epoch":"e","total":%d,"sessions":{}}`, total)
	if err := os.WriteFile(filepath.Join(dir, cn), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAccumulatedUsageReadsTheCounter(t *testing.T) {
	dir := t.TempDir()
	writeCounter(t, dir, "eve", 1234)
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
	writeCounter(t, dir, "gina", 10)
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
	writeCounter(t, dir, "hank", 500)
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
