// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The node serves its PKI and state as one gzipped tar so the panel can keep
// a copy: a restored node keeps its CA, so every issued .ovpn stays valid.
func TestHandleBackupServesPKIAndState(t *testing.T) {
	s := testServer(t)
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	t.Setenv("OVNODE_DATA_DIR", dataDir)
	t.Setenv("OVNODE_OPENVPN_ROOT", filepath.Join(dir, "openvpn"))

	pkiDir := filepath.Join(dir, "openvpn", "server", "pki")
	if err := os.MkdirAll(pkiDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkiDir, "ca.crt"), []byte("CA-PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dataDir, "state")
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "counter.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := do(t, s, http.MethodGet, "/sync/backup", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("backup status = %d, body %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/gzip" {
		t.Fatalf("content type = %q, want application/gzip", ct)
	}

	gz, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	names := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		names[h.Name] = true
	}
	if !names["pki/ca.crt"] {
		t.Errorf("the archive has no pki/ca.crt: %v", names)
	}
	if !names["data/state/counter.json"] {
		t.Errorf("the archive has no data/state/counter.json: %v", names)
	}
}

// The backup route must not be reachable without the API key.
func TestHandleBackupRequiresAuth(t *testing.T) {
	s := testServer(t)
	req, err := http.NewRequest(http.MethodGet, "/sync/backup", nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("backup without a key answered %d, want a refusal", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "API key") {
		t.Errorf("body = %q, want an API key complaint", rec.Body.String())
	}
}
