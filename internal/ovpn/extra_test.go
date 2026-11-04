package ovpn

import (
	"os"
	"path/filepath"
	"testing"

	"ovnode/internal/pki"
	"ovnode/internal/store"
)

func TestDeleteUserRemovesAllCopies(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	t.Setenv("OVNODE_DATA_DIR", root+"/ovnode-data")
	if err := InitPKI(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{
		filepath.Join(root, "server", "pki", "issued"),
		filepath.Join(root, "server", "pki", "private"),
		filepath.Join(root, "server", "pki", "inline", "private"),
		filepath.Join(root, "ovnode-data", "users"),
		filepath.Join(root, "ovnode-data", "sessions"),
		filepath.Join(root, "ovnode-data", "usage"),
	} {
		os.MkdirAll(d, 0o700)
	}
	cn := "testuser"
	// create pki copies
	os.WriteFile(pki.ClientKeyPath(cn), []byte("key"), 0o600)
	os.MkdirAll(filepath.Dir(pki.InlineBundlePath(cn)), 0o700)
	os.WriteFile(pki.InlineBundlePath(cn), []byte("bundle"), 0o600)
	// user dir copies
	dir, _ := store.UserDir(pki.UsersDir(), cn)
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("cert"), 0o644)
	os.WriteFile(filepath.Join(dir, "key.pem"), []byte("key"), 0o600)
	os.WriteFile(filepath.Join(dir, "client.ovpn"), []byte("ovpn"), 0o600)
	store.CreateUser(pki.UsersDir(), cn)

	found, err := DeleteUser(cn)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected found")
	}
	for _, p := range []string{
		pki.IssuedCertPath(cn),
		pki.ClientKeyPath(cn),
		pki.InlineBundlePath(cn),
		filepath.Join(dir, "cert.pem"),
		filepath.Join(dir, "key.pem"),
		filepath.Join(dir, "client.ovpn"),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("file still exists: %s", p)
		}
	}
	if store.UserExists(pki.UsersDir(), cn) {
		t.Fatal("user dir still exists")
	}
}
