package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"

	"ovnode/internal/pki"
	"strings"
	"testing"
)

func TestHandleLogsClampAndValidate(t *testing.T) {
	s := testServer(t)
	// invalid level
	rec := do(t, s, http.MethodGet, "/sync/logs?level=FOO&limit=5", "")
	if rec.Code != http.StatusOK {
		// authorize passes; handler writes fail envelope with 200? check body success
	}
	body := envelopeOf(t, rec)
	if body["success"] != false {
		t.Fatalf("expected failure for invalid level, got %v", body["success"])
	}
	// negative limit
	rec = do(t, s, http.MethodGet, "/sync/logs?level=INFO&limit=-3", "")
	body = envelopeOf(t, rec)
	if body["success"] != false {
		t.Fatalf("expected failure for negative limit")
	}
	// valid
	rec = do(t, s, http.MethodGet, "/sync/logs?level=INFO&limit=10", "")
	body = envelopeOf(t, rec)
	if body["success"] != true {
		t.Fatalf("expected success, got %v", body["msg"])
	}
}

func TestGzipMiddlewareSkipsOVPNDownload(t *testing.T) {
	s := testServer(t)
	h := gzipMiddleware(s.gzipSkip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 1024)))
	})))
	// The download pattern stays raw even through a gzip-eligible request.
	req := httptest.NewRequest(http.MethodGet, "/sync/download/ovpn/uid", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	// Simulate Go 1.22 routing: set Pattern the way ServeMux would.
	req.Pattern = "GET /sync/download/ovpn/{uid}"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatal("expected no gzip for gzipSkip route")
	}
	// The same request without the flag is compressed.
	h2 := gzipMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 1024)))
	}))
	req2 := httptest.NewRequest(http.MethodGet, "/sync/status", nil)
	req2.Header.Set("Accept-Encoding", "gzip")
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, req2)
	if rec2.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("expected gzip without the skip flag")
	}
}

func TestHandleDownloadOVPNAutoCreateHeavy(t *testing.T) {
	s := testServer(t)
	// ensure no profile; auto-create path should succeed with heavy auth
	rec := do(t, s, http.MethodGet, "/sync/download/ovpn/testuser", "")
	// may fail due to missing ovpn binary/env, but should not be 401/429
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusTooManyRequests {
		t.Fatalf("unexpected auth/ratelimit failure: %d", rec.Code)
	}
}

func TestHandleUpdateInvalidVersion(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, http.MethodPost, "/sync/update", `{"version":"1.2"}`)
	body := envelopeOf(t, rec)
	if body["success"] != false {
		t.Fatalf("expected failure, got %v", body["success"])
	}
	if msg, _ := body["msg"].(string); msg != "Invalid target version" {
		t.Fatalf("msg = %q, want %q", msg, "Invalid target version")
	}
}

func TestHandleUpdateLock(t *testing.T) {
	s := testServer(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "install.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\ntrap '' HUP; while [ -e /tmp/ovnode-update-lock-hold ]; do sleep 0.05; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 0); err != nil && !os.IsPermission(err) {
		t.Fatal(err)
	}
	// appDir is computed once in NewServer; the test builds the server
	// directly, so seed the cached path the same way.
	s.appDirPath = dir
	t.Setenv("APP_DIR", dir)

	if err := os.WriteFile("/tmp/ovnode-update-lock-hold", []byte("hold\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove("/tmp/ovnode-update-lock-hold") })

	rec := do(t, s, http.MethodPost, "/sync/update", "")
	body := envelopeOf(t, rec)
	if body["success"] != true {
		t.Fatalf("first update should start, got %v (%s)", body["success"], rec.Body.String())
	}

	rec2 := do(t, s, http.MethodPost, "/sync/update", "")
	body2 := envelopeOf(t, rec2)
	if body2["success"] != false {
		t.Fatalf("second update should be refused, got %v", body2["success"])
	}
	if msg, _ := body2["msg"].(string); !strings.Contains(msg, "update already running") {
		t.Fatalf("msg = %q, want update already running", msg)
	}
}

func TestHandlePushPKIRejectsInvalid(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, http.MethodPut, "/sync/pki", `{"ca_pem":"x","server_cert_pem":"y","server_key_pem":"z"}`)
	body := envelopeOf(t, rec)
	if body["success"] != false {
		t.Fatalf("expected failure, got %v", body["success"])
	}
	if msg, _ := body["msg"].(string); !strings.Contains(msg, "Invalid PKI") {
		t.Fatalf("msg = %q, want Invalid PKI", msg)
	}
}

func TestHandlePushPKIRollsBackPartialWrite(t *testing.T) {
	s := testServer(t)
	root := os.Getenv("OVNODE_OPENVPN_ROOT")
	tmp := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", tmp+"/ca.key")
	run("openssl", "req", "-new", "-x509", "-key", tmp+"/ca.key", "-out", tmp+"/ca.crt", "-days", "365", "-subj", "/CN=Test CA")
	run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", tmp+"/server.key")
	run("openssl", "req", "-new", "-key", tmp+"/server.key", "-out", tmp+"/server.csr", "-subj", "/CN=server")
	run("openssl", "x509", "-req", "-in", tmp+"/server.csr", "-CA", tmp+"/ca.crt", "-CAkey", tmp+"/ca.key", "-CAcreateserial", "-out", tmp+"/server.crt", "-days", "365")

	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(tmp + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	body, _ := json.Marshal(map[string]string{
		"ca_pem":          read("ca.crt"),
		"server_cert_pem": read("server.crt"),
		"server_key_pem":  read("server.key"),
	})

	oldKey := []byte("old-key")
	oldCA := []byte("old-ca")
	if err := os.WriteFile(pki.ServerKey(), oldKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pki.CACert(), oldCA, 0o644); err != nil {
		t.Fatal(err)
	}
	// Force the second write (server cert) to fail after the key write.
	if err := os.Mkdir(pki.ServerCert(), 0o755); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPut, "/sync/pki", bytes.NewReader(body))
	req.Header.Set("key", testKey)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	resp := envelopeOf(t, rec)
	if resp["success"] != false {
		t.Fatalf("expected failure, got %v", resp["success"])
	}
	if msg, _ := resp["msg"].(string); !strings.Contains(msg, "Failed to store pushed PKI") {
		t.Fatalf("msg = %q, want Failed to store pushed PKI", msg)
	}
	gotKey, err := os.ReadFile(pki.ServerKey())
	if err != nil || string(gotKey) != string(oldKey) {
		t.Fatalf("server key not restored: %v %q", err, string(gotKey))
	}
	gotCA, err := os.ReadFile(pki.CACert())
	if err != nil || string(gotCA) != string(oldCA) {
		t.Fatalf("CA not preserved: %v %q", err, string(gotCA))
	}
	if info, err := os.Stat(pki.ServerCert()); err != nil || !info.IsDir() {
		t.Fatalf("server cert path should remain the failing directory: %v", err)
	}
	_ = root
}
