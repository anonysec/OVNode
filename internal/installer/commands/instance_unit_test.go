// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallStateOfUsesInstanceUnitName(t *testing.T) {
	sd := t.TempDir()
	t.Setenv("SystemdDir", sd)
	c := &Config{Instance: "udp443", Service: "udp443.service"}
	app := filepath.Join(t.TempDir(), "app")

	if got := c.InstallStateOf(app); got != StateAbsent {
		t.Fatalf("no unit: got %q, want absent", got)
	}
	if err := os.WriteFile(filepath.Join(sd, "ovnode.service"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := c.InstallStateOf(app); got != StateAbsent {
		t.Fatalf("default unit for another instance: got %q, want absent", got)
	}
	if err := os.WriteFile(filepath.Join(sd, c.Service), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := c.InstallStateOf(app); got != StateUnitOnly {
		t.Fatalf("instance unit: got %q, want unit-only", got)
	}
}
