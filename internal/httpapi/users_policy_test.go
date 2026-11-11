// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"ovnode/internal/fsx"
	"ovnode/internal/ovpn"
	"ovnode/internal/pki"
	"ovnode/internal/store"
)

func providerServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	root := fsx.OpenVPNRoot()
	t.Setenv("LogDir", filepath.Join(root, "logs"))
	t.Setenv("LogFile", filepath.Join(root, "logs", "events.log"))
	t.Setenv("UsersDir", filepath.Join(fsx.OVNodeDir(), "users"))
	t.Setenv("SessionsDir", filepath.Join(fsx.OVNodeDir(), "sessions"))
	t.Setenv("UsageDir", filepath.Join(fsx.OVNodeDir(), "usage"))
	t.Setenv("StatusFile", filepath.Join(root, "server", "status.log"))
	t.Setenv("MgmtPassFile", filepath.Join(root, "server", "mgmt-pass"))
	return s
}

func initRoutePKI(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openvpn"); err != nil {
		t.Skip("openvpn is required")
	}
	if _, err := os.Stat("/usr/share/easy-rsa/easyrsa"); err != nil {
		t.Skip("easy-rsa is required")
	}
	if err := ovpn.InitPKI(); err != nil {
		t.Fatal(err)
	}
}

func assertWorkingProfile(t *testing.T, text, cn string) {
	t.Helper()
	if !strings.HasPrefix(text, "client\n") {
		t.Fatalf("download returned no working profile: %s", text)
	}
	part := func(tag string) []byte {
		_, body, ok := strings.Cut(text, "<"+tag+">\n")
		if !ok {
			t.Fatalf("profile has no %s block", tag)
		}
		body, _, ok = strings.Cut(body, "</"+tag+">")
		if !ok {
			t.Fatalf("profile has no closing %s block", tag)
		}
		return []byte(body)
	}
	pair, err := tls.X509KeyPair(part("cert"), part("key"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || cert.Subject.CommonName != cn {
		t.Fatalf("profile certificate identity: %v (%v)", cert, err)
	}
	caBlock, _ := pem.Decode(part("ca"))
	if caBlock == nil {
		t.Fatal("profile CA does not parse")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	if len(part("tls-crypt")) == 0 {
		t.Fatal("profile TLS key is empty")
	}
}

func TestPolicyBeforeFirstDownloadPreservesWorkingProfile(t *testing.T) {
	s := providerServer(t)
	initRoutePKI(t)
	for _, limit := range []int{0, 1, 3} {
		for _, disabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("limit-%d-disabled-%t", limit, disabled), func(t *testing.T) {
				cn := fmt.Sprintf("policy-%d-%t", limit, disabled)
				name := "Alice " + cn
				status := "activate"
				if disabled {
					status = "deactivate"
				}
				body := fmt.Sprintf(`{"id":%q,"name":%q,"max_logins":%d,"status":%q}`, cn, name, limit, status)
				response := do(t, s, http.MethodPut, "/sync/user", body)
				if env := envelopeOf(t, response); response.Code != http.StatusOK || env["success"] != true || env["msg"] != "User status changed successfully" {
					t.Fatalf("policy PUT: %s", response.Body.String())
				}
				if got := store.ReadName(pki.UsersDir(), cn); got != name {
					t.Errorf("successful policy PUT ignored name: %q, want %q", got, name)
				}
				profile := do(t, s, http.MethodGet, "/sync/download/ovpn/"+cn, "")
				assertWorkingProfile(t, profile.Body.String(), cn)
				cert, err := os.ReadFile(pki.IssuedCertPath(cn))
				if err != nil {
					t.Fatal(err)
				}
				key, err := os.ReadFile(pki.ClientKeyPath(cn))
				if err != nil {
					t.Fatal(err)
				}
				path, err := ovpn.UserProfilePath(cn)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				profile = do(t, s, http.MethodGet, "/sync/download/ovpn/"+cn, "")
				assertWorkingProfile(t, profile.Body.String(), cn)
				newCert, certErr := os.ReadFile(pki.IssuedCertPath(cn))
				newKey, keyErr := os.ReadFile(pki.ClientKeyPath(cn))
				state, stateErr := store.ReadUserState(pki.UsersDir(), cn)
				if certErr != nil || keyErr != nil || !bytes.Equal(cert, newCert) || !bytes.Equal(key, newKey) || stateErr != nil || state.Limit != limit || state.Disabled != disabled || store.ReadName(pki.UsersDir(), cn) != name {
					t.Fatalf("regenerated download changed identity or desired policy: %+v (%v, %v, %v)", state, certErr, keyErr, stateErr)
				}
			})
		}
	}
}

func TestConfigRegenerationPreservesUserPolicy(t *testing.T) {
	s := providerServer(t)
	initRoutePKI(t)
	for _, limit := range []int{0, 1, 3} {
		cn := "config-" + strconv.Itoa(limit)
		disabled := true
		if err := ovpn.CreateUser(cn, "Alice "+cn, limit, &disabled); err != nil {
			t.Fatal(err)
		}
	}
	response := do(t, s, http.MethodPost, "/sync/config", `{"tunnel_address":"vpn.provider.test","protocol":"udp","ovpn_port":1194,"set_new_setting":true}`)
	if envelopeOf(t, response)["success"] != true {
		t.Fatalf("isolated config push failed: %s", response.Body.String())
	}
	for _, limit := range []int{0, 1, 3} {
		cn := "config-" + strconv.Itoa(limit)
		path, err := ovpn.UserProfilePath(cn)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("config push did not invalidate the effective profile cache: %s (%v)", path, err)
		}
		cert, err := os.ReadFile(pki.IssuedCertPath(cn))
		if err != nil {
			t.Fatal(err)
		}
		key, err := os.ReadFile(pki.ClientKeyPath(cn))
		if err != nil {
			t.Fatal(err)
		}
		profile := do(t, s, http.MethodGet, "/sync/download/ovpn/"+cn, "")
		assertWorkingProfile(t, profile.Body.String(), cn)
		if !strings.Contains(profile.Body.String(), "<connection>") ||
			!strings.Contains(profile.Body.String(), "remote vpn.provider.test 1194 udp") {
			t.Error("regenerated profile ignored the pushed client configuration")
		}
		newCert, certErr := os.ReadFile(pki.IssuedCertPath(cn))
		newKey, keyErr := os.ReadFile(pki.ClientKeyPath(cn))
		state, stateErr := store.ReadUserState(pki.UsersDir(), cn)
		if certErr != nil || keyErr != nil || !bytes.Equal(cert, newCert) || !bytes.Equal(key, newKey) || stateErr != nil || state.Limit != limit || !state.Disabled || store.ReadName(pki.UsersDir(), cn) != "Alice "+cn {
			t.Fatalf("config regeneration changed policy or credentials: %+v (%v, %v, %v)", state, certErr, keyErr, stateErr)
		}
	}
}

func TestDownloadRepairsMissingCertificateWithoutReplacingKey(t *testing.T) {
	s := providerServer(t)
	initRoutePKI(t)
	disabled := true
	if err := ovpn.CreateUser("alice", "Alice", 3, &disabled); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(pki.ClientKeyPath("alice"))
	if err != nil {
		t.Fatal(err)
	}
	path, err := ovpn.UserProfilePath("alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{pki.IssuedCertPath("alice"), path} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	response := do(t, s, http.MethodGet, "/sync/download/ovpn/alice", "")
	assertWorkingProfile(t, response.Body.String(), "alice")
	after, err := os.ReadFile(pki.ClientKeyPath("alice"))
	if err != nil || !bytes.Equal(key, after) {
		t.Fatalf("missing-certificate repair replaced existing key bytes: %v", err)
	}
	state, err := store.ReadUserState(pki.UsersDir(), "alice")
	if err != nil || state.Limit != 3 || !state.Disabled || store.ReadName(pki.UsersDir(), "alice") != "Alice" {
		t.Fatalf("missing-certificate repair changed policy: %+v (%v)", state, err)
	}
}

func TestLegacyPrivateDownloadCreatesDefaultPolicy(t *testing.T) {
	s := providerServer(t)
	initRoutePKI(t)
	response := do(t, s, http.MethodGet, "/sync/download/ovpn/legacy", "")
	assertWorkingProfile(t, response.Body.String(), "legacy")
	state, err := store.ReadUserState(pki.UsersDir(), "legacy")
	if err != nil || !state.LimitSet || state.Limit != 1 || state.Disabled {
		t.Fatalf("legacy private download default: %+v (%v)", state, err)
	}
}

func TestUserPolicyPUTRejectsInvalidPolicyWithoutPartialWrites(t *testing.T) {
	s := providerServer(t)
	if err := ovpn.ApplyUserPolicy("alice", "Alice", 2, true); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"id":"alice","name":"Bob","max_logins":3,"status":"invalid"}`, `{"id":"alice","name":"bad\nname","max_logins":3,"status":"activate"}`} {
		response := do(t, s, http.MethodPut, "/sync/user", body)
		if env := envelopeOf(t, response); response.Code != http.StatusOK || env["success"] != false {
			t.Errorf("invalid complete policy reported success: %s", response.Body.String())
		}
		state, err := store.ReadUserState(pki.UsersDir(), "alice")
		if err != nil || state.Limit != 2 || !state.Disabled || store.ReadName(pki.UsersDir(), "alice") != "Alice" {
			t.Errorf("invalid complete policy changed desired state: %+v (%v)", state, err)
		}
	}
}

func TestUserPolicyPUTKeepsLegacyDefaults(t *testing.T) {
	s := providerServer(t)
	if err := ovpn.ApplyUserPolicy("alice", "Alice", 3, true); err != nil {
		t.Fatal(err)
	}
	response := do(t, s, http.MethodPut, "/sync/user", `{"id":"alice"}`)
	if envelopeOf(t, response)["success"] != true {
		t.Fatalf("legacy default activation failed: %s", response.Body.String())
	}
	state, err := store.ReadUserState(pki.UsersDir(), "alice")
	if err != nil || state.Limit != 3 || state.Disabled || store.ReadName(pki.UsersDir(), "alice") != "Alice" {
		t.Fatalf("legacy default activation changed unspecified name/limit: %+v (%v)", state, err)
	}
}

func TestUserDeleteReportsUnverifiableRevocation(t *testing.T) {
	s := providerServer(t)
	initRoutePKI(t)
	if err := ovpn.CreateUser("alice", "Alice", 3, nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(pki.PKIDir(), "index.txt")
	index, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, row := range strings.Split(string(index), "\n") {
		if !strings.Contains(row, "\t/CN=alice") {
			rows = append(rows, row)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(rows, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	response := do(t, s, http.MethodDelete, "/sync/user/alice", "")
	if env := envelopeOf(t, response); response.Code != http.StatusOK || env["success"] != false || env["msg"] != "Failed to delete user" {
		t.Fatalf("unverifiable revocation returned a successful HTTP envelope: %s", response.Body.String())
	}
	state, err := store.ReadUserState(pki.UsersDir(), "alice")
	if err != nil || !state.Disabled || state.Limit != 3 || !store.UserExists(pki.UsersDir(), "alice") {
		t.Fatalf("failed HTTP deletion did not retain disabled desired state: %+v (%v)", state, err)
	}
}

func TestUserPolicyPUTPreservesFailureEnvelope(t *testing.T) {
	s := providerServer(t)
	if err := ovpn.ApplyUserPolicy("alice", "Alice", 2, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(pki.UsersDir(), "alice", "state")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		body, message string
	}{
		{`{"id":"alice","name":"Bob","max_logins":3,"status":"activate"}`, "Failed to update user login limit"},
		{`{"id":"alice","name":"Bob","max_logins":0,"status":"deactivate"}`, "Failed to update user login limit"},
		{`{"id":"alice","name":"Bob","status":"activate"}`, "Failed to change user status"},
		{`{"id":"alice","name":"Bob","max_logins":-1,"status":"activate"}`, "Failed to change user status"},
	} {
		response := do(t, s, http.MethodPut, "/sync/user", test.body)
		want := fmt.Sprintf("{\"success\":false,\"msg\":%q,\"data\":null}\n", test.message)
		if response.Code != http.StatusOK || response.Body.String() != want {
			t.Errorf("historical failed envelope changed: got %s, want %s", response.Body.String(), want)
		}
		if _, err := os.Stat(filepath.Join(pki.UsersDir(), "alice", "name")); !os.IsNotExist(err) {
			t.Errorf("failed atomic policy wrote a split name: %v", err)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, before, 0o640); err != nil {
		t.Fatal(err)
	}
	state, err := store.ReadUserState(pki.UsersDir(), "alice")
	if err != nil || state.Limit != 2 || !state.Disabled || store.ReadName(pki.UsersDir(), "alice") != "Alice" {
		t.Fatalf("failed atomic policy changed existing desired state: %+v (%v)", state, err)
	}
}
