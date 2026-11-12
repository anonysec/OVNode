// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"strings"
	"testing"
)

func TestServerSANOptionIncludesConfiguredNames(t *testing.T) {
	t.Setenv("TlsDomain", "panel.example, 203.0.113.9, localhost")
	got := serverSANOption()
	for _, want := range []string{"DNS:server", "DNS:localhost", "DNS:panel.example", "IP:203.0.113.9"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s missing from %s", want, got)
		}
	}
}

func TestServerSANOptionSkipsInvalidValues(t *testing.T) {
	t.Setenv("TlsDomain", "exa mple, panel.example")
	got := serverSANOption()
	if strings.Contains(got, "exa mple") {
		t.Fatalf("invalid SAN leaked: %s", got)
	}
	if !strings.Contains(got, "DNS:panel.example") {
		t.Fatalf("valid SAN missing: %s", got)
	}
}
