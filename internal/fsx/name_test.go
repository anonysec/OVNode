package fsx

import "testing"

func TestSafeCNRejectsLeadingDot(t *testing.T) {
	for _, cn := range []string{".", "..", "...", ".tmp-1", ".lock.x"} {
		if _, err := SafeCN(cn); err == nil {
			t.Fatalf("SafeCN(%q) should fail", cn)
		}
	}
	if _, err := SafeCN("ok.name"); err != nil {
		t.Fatalf("SafeCN valid failed: %v", err)
	}
}

func TestHookCNRejectsLeadingDot(t *testing.T) {
	if HookCNValid(".u1") {
		t.Fatal("leading dot should be rejected")
	}
	if !HookCNValid("u1") {
		t.Fatal("valid CN rejected")
	}
}
