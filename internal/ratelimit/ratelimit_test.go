// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ratelimit

import (
	"testing"
)

func TestAllowHeavyAndPruning(t *testing.T) {
	l := New()
	for i := 0; i < heavyMax; i++ {
		ok, _ := l.AllowHeavy("client1")
		if !ok {
			t.Fatalf("call %d should be allowed", i)
		}
	}
	// Exceeded
	ok, retry := l.AllowHeavy("client1")
	if ok {
		t.Fatal("call over heavyMax should be rejected")
	}
	if retry <= 0 {
		t.Fatalf("expected positive retry duration, got %v", retry)
	}
}
