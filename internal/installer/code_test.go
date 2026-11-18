// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package installer

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotCodeCarriesVersionAndMode(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "ovnode")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "VERSION"), []byte("2.0.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "ovnode-server"), []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	snap, err := SnapshotCode(app, filepath.Join(root, "backups"), "node")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(snap)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	modes := map[string]int64{}
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		modes[hdr.Name] = hdr.Mode
	}
	if modes["ovnode/VERSION"] == 0 {
		t.Fatalf("snapshot missing ovnode/VERSION: %v", modes)
	}
	if modes["ovnode/ovnode-server"]&0o111 == 0 {
		t.Fatalf("binary lost its executable bit: %o", modes["ovnode/ovnode-server"])
	}
}
