// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPortsStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	os.MkdirAll(filepath.Join(dir, "ovnode"), 0o755)
	WritePortsState([]int{8080, 9090})
	st := ReadPortsState()
	if !st.Pinned || len(st.Ports) != 2 {
		t.Fatalf("got %+v", st)
	}
	if PortsEffective([]int{1194})[0] != 8080 {
		t.Fatal("effective wrong")
	}
}

func TestDNSEffective(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	os.MkdirAll(filepath.Join(dir, "ovnode"), 0o755)
	WriteDNSState("8.8.8.8", "1.1.1.1")
	got := DNSEffective("9.9.9.9", "9.9.9.9")
	if got[0] != "8.8.8.8" {
		t.Fatalf("got %v", got)
	}
}

func TestIPv6Effective(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	os.MkdirAll(filepath.Join(dir, "ovnode"), 0o755)
	WriteIPv6State(true, "fd00::/64")
	en, pref := IPv6Effective(false, "fd42::/64")
	if !en || pref != "fd00::/64" {
		t.Fatalf("got %v %s", en, pref)
	}
}

func TestValidateIPAndPrefix(t *testing.T) {
	// IPv4
	if got := ValidateIP("1.2.3.4"); got != "1.2.3.4" {
		t.Errorf("ValidateIP(1.2.3.4) = %q, want 1.2.3.4", got)
	}
	if got := ValidateIP("999.2.3.4"); got != "" {
		t.Errorf("ValidateIP(999.2.3.4) = %q, want empty", got)
	}
	// IPv6
	if got := ValidateIP("2001:db8::1"); got != "2001:db8::1" {
		t.Errorf("ValidateIP(2001:db8::1) = %q, want 2001:db8::1", got)
	}
	if got := ValidateIP("invalid::ip::xyz"); got != "" {
		t.Errorf("ValidateIP(invalid::ip::xyz) = %q, want empty", got)
	}

	// Prefix
	if got := ValidatePrefix("fd42:42:42:42::/64"); got != "fd42:42:42:42::/64" {
		t.Errorf("ValidatePrefix valid = %q", got)
	}
	if got := ValidatePrefix("192.168.1.0/24"); got != "" {
		t.Errorf("ValidatePrefix IPv4 = %q, want empty", got)
	}
	if got := ValidatePrefix("fd42:42:42:42::"); got != "" {
		t.Errorf("ValidatePrefix without mask = %q, want empty", got)
	}
}
