// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestLockRejectsPlantedSymlink(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root required for dropped-UID fixture")
	}
	dir, err := os.MkdirTemp("", "ovnode-lock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "private-file")
	if err := os.WriteFile(target, []byte("fixture-only"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(target, 0, 65534); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.Mkdir(runtimeDir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(runtimeDir, 0, 65534); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeDir, 0o770); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(runtimeDir, ".lock.alice")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	plant := exec.CommandContext(ctx, "ln", "-s", target, lock)
	plant.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if output, err := plant.CombinedOutput(); err != nil {
		t.Fatalf("plant fixture symlink: %v: %s", err, output)
	}
	called := false
	err = Lock(lock, 0o660, func() error { called = true; return nil })
	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("planted lock changed a protected target to %04o", info.Mode().Perm())
	}
	read := exec.CommandContext(ctx, "cat", target)
	read.SysProcAttr = plant.SysProcAttr
	if output, err := read.Output(); err == nil {
		t.Errorf("planting UID can now read the secret: %q", output)
	}
	if err == nil || called {
		t.Errorf("Lock accepted a symlink: err=%v callback=%v", err, called)
	}
}

func TestLockRejectsNonRegularFiles(t *testing.T) {
	for _, kind := range []string{"directory", "fifo", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "lock")
			var err error
			switch kind {
			case "directory":
				err = os.Mkdir(path, 0o700)
			case "fifo":
				err = syscall.Mkfifo(path, 0o600)
			case "hardlink":
				target := filepath.Join(dir, "private")
				if err = os.WriteFile(target, nil, 0o600); err == nil {
					err = os.Link(target, path)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			called := false
			if err := Lock(path, 0o660, func() error { called = true; return nil }); err == nil || called {
				t.Fatalf("Lock accepted %s: err=%v callback=%v", kind, err, called)
			}
		})
	}
}

func TestLockSerializesSeparateOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	var active atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := Lock(path, 0o600, func() error {
				if n := active.Add(1); n != 1 {
					t.Errorf("%d simultaneous lock holders", n)
				}
				time.Sleep(time.Millisecond)
				active.Add(-1)
				return nil
			}); err != nil {
				t.Error(err)
			}
		}()
	}
	close(start)
	wg.Wait()
}
