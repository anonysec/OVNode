// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The template is the operator's file: an edit to it must reach the next
// profile. A hardcoded preamble would ignore it.
func TestBuildTemplateUsesTheTemplateBody(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client-common.txt")
	body := "client\ndev tun\nproto udp\nremote 10.9.0.1 1194\n# a note for humans\nverb 2\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := BuildTemplate(path, Parts{
		ClientCert: "CERT",
		ClientKey:  "KEY",
		CACert:     "CA",
		TLSCrypt:   "PSK",
	})
	if err != nil {
		t.Fatalf("BuildTemplate: %v", err)
	}
	if !strings.Contains(got, "remote 10.9.0.1 1194") {
		t.Errorf("the template's remote line is missing:\n%s", got)
	}
	if strings.Contains(got, "a note for humans") {
		t.Error("a comment line survived into the profile")
	}
	for _, want := range []string{"<ca>\nCA\n</ca>", "<cert>\nCERT\n</cert>", "<key>\nKEY\n</key>", "<tls-crypt>\nPSK\n</tls-crypt>"} {
		if !strings.Contains(got, want) {
			t.Errorf("the profile is missing %q:\n%s", want, got)
		}
	}
}

// A missing template is an error, not a silently empty profile: the panel
// would hand the user a file that cannot connect.
func TestBuildTemplateReportsAMissingTemplate(t *testing.T) {
	if _, err := BuildTemplate(filepath.Join(t.TempDir(), "absent.txt"), Parts{}); err == nil {
		t.Fatal("BuildTemplate accepted a missing template")
	}
}
