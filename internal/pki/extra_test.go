package pki

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureSecretPerms(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	t.Setenv("OVNODE_DATA_DIR", root+"/ovnode-data")
	os.MkdirAll(filepath.Join(root, "server", "pki", "private"), 0o755)
	os.WriteFile(filepath.Join(root, "server", "pki", "private", "ca.key"), []byte("k"), 0o644)
	os.MkdirAll(filepath.Join(root, "ovnode-data", "users", "u1"), 0o755)
	EnsureSecretPerms()
	info, err := os.Stat(filepath.Join(root, "server", "pki", "private"))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("private dir mode = %v, want 0700", info.Mode().Perm())
	}
	fi, _ := os.Stat(filepath.Join(root, "server", "pki", "private", "ca.key"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key mode = %v, want 0600", fi.Mode().Perm())
	}
	ui, _ := os.Stat(filepath.Join(root, "ovnode-data", "users", "u1"))
	if ui.Mode().Perm() != 0o700 {
		t.Fatalf("user dir mode = %v, want 0700", ui.Mode().Perm())
	}
}
