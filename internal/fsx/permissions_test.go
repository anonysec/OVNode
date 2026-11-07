// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package fsx

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestTraversalOnlyParentReadProcess(t *testing.T) {
	path := os.Getenv("OVNODE_TEST_TRAVERSAL_FILE")
	if path == "" {
		return
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "public" {
		t.Fatalf("traversal fixture is not readable through the standard API: %q (%v)", data, err)
	}
	f, err := OpenFileNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if data, err := io.ReadAll(f); err != nil || string(data) != "public" {
		t.Fatalf("checked file read: %q (%v)", data, err)
	}
}

func TestOpenFileNoFollowAllowsTraversalOnlyParents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required to drop UID")
	}
	dir, err := os.MkdirTemp("", "ovnode-traversal-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(dir, "traversal-only")
	if err := os.Mkdir(parent, 0o711); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "public")
	if err := os.WriteFile(path, []byte("public"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	exe = filepath.Join(dir, "reader")
	if err := os.WriteFile(exe, data, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestTraversalOnlyParentReadProcess$")
	cmd.Env = append(os.Environ(), "OVNODE_TEST_TRAVERSAL_FILE="+path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 65533}}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("checked read required listing an unrelated parent: %v\n%s", err, output)
	}
}
