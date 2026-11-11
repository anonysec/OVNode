package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isolate(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DataDir", dir)
	t.Setenv("Instance", "unit-test")
	t.Setenv("Proto", "")
	t.Setenv("VpnPort", "")
	t.Setenv("ExtraPorts", "")
	t.Setenv("EnableIpv6", "")
	t.Setenv("VpnDns1", "")
	t.Setenv("VpnDns2", "")
	t.Setenv("Ipv6Prefix", "")
}

func TestDefaultsAreValid(t *testing.T) {
	isolate(t)
	s := Defaults()
	if err := s.Validate(); err != nil {
		t.Fatalf("defaults do not validate: %v", err)
	}
	if s.Protocol != ProtoUDP || s.Port != 1194 || s.CipherFirst != CipherAES128 || s.TLSMin != "1.3" {
		t.Fatalf("unexpected defaults: %+v", s)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	isolate(t)
	s := Defaults()
	s.Protocol = ProtoBoth
	s.Port = 443
	s.ExtraPorts = []int{8443}
	s.MaxClients = 500
	s.Mssfix = 1350
	s.DNSSecondary = "1.0.0.1"
	if err := Save(s); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(Path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != ProtoBoth || got.Port != 443 || got.MaxClients != 500 || got.Mssfix != 1350 {
		t.Fatalf("round trip lost fields: %+v", got)
	}
	data, _ := os.ReadFile(Path())
	if !strings.Contains(string(data), `"Protocol": "both"`) {
		t.Fatalf("settings are not PascalCase JSON:\n%s", data)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	isolate(t)
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if s.Port != 1194 {
		t.Fatalf("port = %d", s.Port)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	isolate(t)
	if err := os.MkdirAll(filepath.Dir(Path()), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(), []byte(`{"Protocol":"udp","Port":1194,"Typo":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("unknown field was accepted")
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	isolate(t)
	s := Defaults()
	s.Mssfix = 9000
	if err := Save(s); err == nil {
		t.Fatal("invalid settings were saved")
	}
	if _, err := os.Stat(Path()); !os.IsNotExist(err) {
		t.Fatal("an invalid file was written")
	}
}

func TestValidate(t *testing.T) {
	base := func() Server {
		isolate(t)
		return Defaults()
	}
	cases := []struct {
		name   string
		mutate func(*Server)
		ok     bool
	}{
		{"protocol", func(s *Server) { s.Protocol = "sctp" }, false},
		{"port", func(s *Server) { s.Port = 0 }, false},
		{"extra dup", func(s *Server) { s.ExtraPorts = []int{s.Port} }, false},
		{"clients", func(s *Server) { s.MaxClients = 0 }, false},
		{"keepalive order", func(s *Server) { s.KeepalivePing = 100; s.KeepaliveTimeout = 60 }, false},
		{"dns", func(s *Server) { s.DNSPrimary = "dns.example" }, false},
		{"route", func(s *Server) { s.PushRoutes = []string{"10.0.0.0/33"} }, false},
		{"ipv6", func(s *Server) { s.IPv6Enabled = true; s.IPv6Prefix = "10.0.0.0/24" }, false},
		{"mtu", func(s *Server) { s.TunMTU = 900 }, false},
		{"mssfix", func(s *Server) { s.Mssfix = 1600 }, false},
		{"cipher", func(s *Server) { s.CipherFirst = "des" }, false},
		{"tls", func(s *Server) { s.TLSMin = "1.1" }, false},
		{"reneg", func(s *Server) { s.RenegSec = 10 }, false},
		{"verb", func(s *Server) { s.Verb = 9 }, false},
		{"valid both", func(s *Server) { s.Protocol = ProtoBoth; s.Port = 443; s.ExtraPorts = []int{8443} }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			tc.mutate(&s)
			err := s.Validate()
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("invalid settings passed validation")
			}
		})
	}
}

func TestProtosAndCiphers(t *testing.T) {
	if got := (Server{Protocol: ProtoBoth}).Protos(); len(got) != 2 || got[0] != ProtoUDP || got[1] != ProtoTCP {
		t.Fatalf("both = %v", got)
	}
	if got := (Server{Protocol: ProtoTCP}).Protos(); len(got) != 1 || got[0] != ProtoTCP {
		t.Fatalf("tcp = %v", got)
	}
	ciphers := (Server{CipherFirst: CipherChaCha}).DataCiphers()
	if !strings.HasPrefix(ciphers, CipherChaCha+":") || !strings.Contains(ciphers, CipherAES128) {
		t.Fatalf("data ciphers = %s", ciphers)
	}
}
