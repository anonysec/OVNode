// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package settings

import (
	"os"
	"testing"
)

func TestLimitPolicyDefaultsToReserve(t *testing.T) {
	isolate(t)
	got, err := LoadLimitPolicy()
	if err != nil {
		t.Fatalf("LoadLimitPolicy: %v", err)
	}
	if got != LimitReserve {
		t.Fatalf("default policy = %q, want reserve", got)
	}
}

func TestLimitPolicyRoundTrip(t *testing.T) {
	isolate(t)
	for _, want := range []LimitPolicy{LimitStrict, LimitTakeover, LimitReserve} {
		if err := SaveLimitPolicy(want); err != nil {
			t.Fatalf("save %q: %v", want, err)
		}
		got, err := LoadLimitPolicy()
		if err != nil {
			t.Fatalf("load %q: %v", want, err)
		}
		if got != want {
			t.Fatalf("round trip = %q, want %q", got, want)
		}
	}
	info, err := os.Stat(LimitPolicyPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %o, want 644", info.Mode().Perm())
	}
}

func TestLimitPolicyNormalizesEmptyToReserve(t *testing.T) {
	isolate(t)
	if err := os.WriteFile(LimitPolicyPath(), []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadLimitPolicy()
	if err != nil {
		t.Fatalf("empty policy: %v", err)
	}
	if got != LimitReserve {
		t.Fatalf("empty policy = %q, want reserve", got)
	}
}

func TestLimitPolicyRejectsUnknownValue(t *testing.T) {
	isolate(t)
	if _, err := NormalizeLimitPolicy("nope"); err == nil {
		t.Fatal("unknown policy accepted")
	}
	if err := SaveLimitPolicy(LimitPolicy("nope")); err == nil {
		t.Fatal("unknown policy saved")
	}
	if err := os.WriteFile(LimitPolicyPath(), []byte("nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadLimitPolicy()
	if err == nil {
		t.Fatal("invalid file loaded without an error")
	}
	if got != LimitReserve {
		t.Fatalf("invalid file fallback = %q, want reserve", got)
	}
}
