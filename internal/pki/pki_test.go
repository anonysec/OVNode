// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package pki

import (
	"testing"
)

func TestDaysUntilOpensslDate(t *testing.T) {
	raw := "nextUpdate=Aug 28 12:00:00 2027 GMT\n"
	d := DaysUntilOpensslDate(raw)
	if d == nil {
		t.Fatal("nil")
	}
	if *d < 0 {
		t.Fatalf("negative: %d", *d)
	}
}
