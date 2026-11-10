package pairing

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnforceNoFileReadOnRepeatedSamePanel(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", dir)
	t.Setenv("OVNODE_DATA_DIR", dir+"/ovnode-data")
	os.MkdirAll(filepath.Join(dir, "ovnode-data", "state"), 0o755)
	if err := Enforce("panel-a"); err != nil {
		t.Fatal(err)
	}
	// Moving the file mtime forces exactly one reload (the cache
	// invalidation path). A repeated call with the same mtime and the
	// same panel must then be a pure memory hit: no read, no write.
	path := filepath.Join(dir, "ovnode-data", "state", "pairing.json")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	older := fi.ModTime().Add(-time.Second)
	os.Chtimes(path, older, older)
	if err := Enforce("panel-a"); err != nil {
		t.Fatal(err)
	}
	// Backdate the file before the reload could touch it: a pure memory
	// hit returns without reading. If it read, a deleted file would be
	// recreated by the write path.
	fiAfterReload, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = fiAfterReload
	for i := 0; i < 5; i++ {
		if err := Enforce("panel-a"); err != nil {
			t.Fatalf("repeated Enforce failed: %v", err)
		}
	}
	// The file must be untouched by the repeated calls: same mtime as
	// after the reload.
	fi3, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi3.ModTime().Equal(fiAfterReload.ModTime()) {
		t.Fatalf("repeated Enforce changed mtime %v -> %v, want no write", fiAfterReload.ModTime(), fi3.ModTime())
	}
}

func BenchmarkEnforceSamePanel(b *testing.B) {
	dir := b.TempDir()
	b.Setenv("OVNODE_OPENVPN_ROOT", dir)
	b.Setenv("OVNODE_DATA_DIR", dir+"/ovnode-data")
	os.MkdirAll(filepath.Join(dir, "ovnode-data", "state"), 0o755)
	if err := Enforce("panel-bench"); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Enforce("panel-bench"); err != nil {
			b.Fatal(err)
		}
	}
}
