// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import "testing"

// TestSanitizeKeepsTheFileNameSafe pins the sanitizing the bash hook did
// with sed: everything outside [A-Za-z0-9_.-] becomes an underscore.
func TestSanitizeKeepsTheFileNameSafe(t *testing.T) {
	cases := map[string]string{
		"u1":            "u1",
		"user.name":     "user.name",
		"user_name":     "user_name",
		"user-name":     "user-name",
		"a/b":           "a_b",
		"-flag":         "-flag",
		"a b":           "a_b",
		"../etc/passwd": ".._etc_passwd",
	}
	for in, want := range cases {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHookCNValidFailsClosed covers the names that must never reach the
// filesystem: empty, too long, an option-looking dash and the two path
// components that walk out of the tree.
func TestHookCNValidFailsClosed(t *testing.T) {
	cases := map[string]bool{
		"u1":      true,
		"_u1":     true,
		".u1":     true,
		"u-1":     true,
		"a.b.c":   true,
		"":        false,
		"-flag":   false,
		".":       false,
		"..":      false,
		"a b":     false,
		"u1/../x": false,
	}
	for in, want := range cases {
		if got := HookCNValid(in); got != want {
			t.Errorf("HookCNValid(%q) = %v, want %v", in, got, want)
		}
	}
	// The hook sanitizes first, so a name with a space is usable after the
	// sanitize — that is the point of sanitizing.
	if !HookCNValid(Sanitize("a b")) {
		t.Error("a sanitized name with a space must be accepted")
	}
	long := ""
	for i := 0; i < 65; i++ {
		long += "a"
	}
	if HookCNValid(long) {
		t.Error("a 65 character CN must be refused")
	}
}
