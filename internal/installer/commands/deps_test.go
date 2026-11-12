// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package commands

import "testing"

func TestPackageManagerMatrix(t *testing.T) {
	only := func(name string) func(string) bool {
		return func(c string) bool { return c == name }
	}
	tests := []struct {
		name      string
		has       func(string) bool
		wantUp    string
		wantIn    string
		wantFound bool
	}{
		{"apt", only("apt-get"), "apt-get", "apt-get", true},
		{"dnf", only("dnf"), "dnf", "dnf", true},
		{"yum", only("yum"), "yum", "yum", true},
		{"pacman", only("pacman"), "pacman", "pacman", true},
		{"apk", only("apk"), "apk", "apk", true},
		{"unknown", func(string) bool { return false }, "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			update, install, ok := packageManager(tt.has)
			if ok != tt.wantFound {
				t.Fatalf("ok = %v, want %v", ok, tt.wantFound)
			}
			if !ok {
				return
			}
			if update[0] != tt.wantUp || install[0] != tt.wantIn {
				t.Fatalf("update=%v install=%v", update, install)
			}
		})
	}
}
