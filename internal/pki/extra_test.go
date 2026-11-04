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

func TestValidatePushedKeyTrailingGarbage(t *testing.T) {
	// minimal CA
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	t.Setenv("OVNODE_DATA_DIR", root+"/ovnode-data")
	// use writeTestCA? unexported in same package
	writeTestCA(t, root)
	caPEM, _ := os.ReadFile(filepath.Join(root, "server", "pki", "ca.crt"))
	key, _ := os.ReadFile(filepath.Join(root, "server", "pki", "private", "ca.key"))
	// generate a server cert signed by CA? skip; test only trailing garbage detection on key
	badKey := string(key) + "\nfoo"
	if err := ensureSinglePEM(badKey); err == nil {
		t.Fatal("expected trailing garbage error")
	}
	_ = caPEM
}

func TestEnsureSecretPermsDoesNotChmodSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	t.Setenv("OVNODE_DATA_DIR", root+"/ovnode-data")
	pkiDir := filepath.Join(root, "server", "pki")
	if err := os.MkdirAll(filepath.Join(pkiDir, "private"), 0o755); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(pkiDir, "private", "a.key")
	if err := os.WriteFile(keyPath, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("target"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(pkiDir, "private", "link.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	EnsureSecretPerms()

	fi, err := os.Stat(keyPath)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("a.key mode = %v, want 0600", fi.Mode().Perm())
	}
	ti, err := os.Stat(target)
	if err != nil || ti.Mode().Perm() != 0o644 {
		t.Fatalf("symlink target mode = %v, want 0644", ti.Mode().Perm())
	}
}

func TestCRLMatchesCA(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVNODE_OPENVPN_ROOT", root)
	t.Setenv("OVNODE_DATA_DIR", root+"/ovnode-data")
	writeTestCA(t, root)
	if err := GenerateCRL(); err != nil {
		t.Fatal(err)
	}
	if !CRLMatchesCA() {
		t.Fatal("CRLMatchesCA() = false, want true")
	}
	// A different CA must not match the existing CRL.
	root2 := t.TempDir()
	writeTestCA(t, root2)
	data, err := os.ReadFile(filepath.Join(root2, "server", "pki", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "server", "pki", "ca.crt"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if CRLMatchesCA() {
		t.Fatal("CRLMatchesCA() = true, want false")
	}
}
