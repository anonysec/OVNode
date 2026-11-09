// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package installer

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func buildTree(t *testing.T) (appDir, nodeData, ovpnRoot, backupRoot string) {
	t.Helper()
	base := t.TempDir()
	appDir = filepath.Join(base, "app")
	nodeData = filepath.Join(base, "data")
	ovpnRoot = filepath.Join(base, "openvpn")
	backupRoot = filepath.Join(base, "backup")
	writeTree(t, appDir, map[string]string{".env": "NODE_NAME=n1\nAPI_KEY=abc\n"})
	writeTree(t, nodeData, map[string]string{"state/x.json": `{"ok":true}`, "users/u1/limit": "2"})
	writeTree(t, ovpnRoot, map[string]string{"server/server.conf": "port 1194\n", "ovnode/u1/config": "client\n"})
	return appDir, nodeData, ovpnRoot, backupRoot
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestBundleRestoreRoundTrip(t *testing.T) {
	appDir, nodeData, ovpnRoot, backupRoot := buildTree(t)
	// A symlink inside the tree must never be archived or followed.
	if err := os.Symlink("/etc/passwd", filepath.Join(nodeData, "evil-link")); err != nil {
		t.Fatal(err)
	}
	bundle, err := Bundle(appDir, nodeData, ovpnRoot, backupRoot, "n1", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(bundle)
	if err != nil {
		t.Fatal(err)
	}
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(h.Name, "evil-link") {
			t.Fatalf("bundle contains symlink member %s", h.Name)
		}
		if h.Typeflag != tar.TypeReg {
			t.Fatalf("bundle member %s has type %d, want regular", h.Name, h.Typeflag)
		}
	}
	gr.Close()
	f.Close()

	target := t.TempDir()
	newApp := filepath.Join(target, "app")
	newData := filepath.Join(target, "data")
	newOvpn := filepath.Join(target, "openvpn")
	if err := Restore(bundle, newApp, newData, newOvpn); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(newApp, ".env")); got != "NODE_NAME=n1\nAPI_KEY=abc\n" {
		t.Fatalf(".env = %q", got)
	}
	if got := readFile(t, filepath.Join(newData, "state/x.json")); got != `{"ok":true}` {
		t.Fatalf("state = %q", got)
	}
	if got := readFile(t, filepath.Join(newData, "users/u1/limit")); got != "2" {
		t.Fatalf("limit = %q", got)
	}
	if got := readFile(t, filepath.Join(newOvpn, "server/server.conf")); got != "port 1194\n" {
		t.Fatalf("server.conf = %q", got)
	}
	if _, err := os.Lstat(filepath.Join(newData, "evil-link")); !os.IsNotExist(err) {
		t.Fatalf("symlink restored: %v", err)
	}
}

func TestRestoreRejectsTraversalAndLinks(t *testing.T) {
	_, _, _, backupRoot := buildTree(t)
	if err := os.MkdirAll(backupRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	badHeaders := []*tar.Header{
		{Name: "../evil", Typeflag: tar.TypeReg, Size: 3, Mode: 0o644},
		{Name: "/abs/evil", Typeflag: tar.TypeReg, Size: 3, Mode: 0o644},
		{Name: "data/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "data/link", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"},
	}
	for _, bad := range badHeaders {
		bundle := filepath.Join(backupRoot, "bad.tar.gz")
		writeBadBundle(t, bundle, bad)
		target := t.TempDir()
		if err := Restore(bundle, filepath.Join(target, "app"), filepath.Join(target, "data"), filepath.Join(target, "openvpn")); err == nil {
			t.Fatalf("Restore accepted member %s (type %d)", bad.Name, bad.Typeflag)
		}
		if _, err := os.Stat(filepath.Join(target, "evil")); !os.IsNotExist(err) {
			t.Fatalf("traversal member %s wrote outside staging", bad.Name)
		}
	}
}

func writeBadBundle(t *testing.T, path string, bad *tar.Header) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gr := gzip.NewWriter(f)
	tw := tar.NewWriter(gr)
	writeHdr := func(h *tar.Header, body string) {
		if h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink {
			if err := tw.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
			return
		}
		h.Size = int64(len(body))
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatal(err)
		}
	}
	writeHdr(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Mode: 0o644}, `{"format":"ovnode-state","members":{}}`)
	writeHdr(bad, "x")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gr.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
