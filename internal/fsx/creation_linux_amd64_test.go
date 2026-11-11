// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package fsx

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func creationFixture(t *testing.T) (string, string, context.Context) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root required for owned creation fixtures")
	}
	dir, err := os.MkdirTemp("", "ovnode-creation-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	bin := filepath.Join(dir, "creation-helper")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./testdata/permission-transition")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("creation fixture build: %v\n%s", err, output)
	}
	return dir, bin, ctx
}

func TestCreatedDirectoryDescriptorSurvivesExchange(t *testing.T) {
	dir, bin, ctx := creationFixture(t)
	for _, shared := range []bool{true, false} {
		name := "writable-parent"
		if !shared {
			name = "trusted-parent"
		}
		t.Run(name, func(t *testing.T) {
			parent := filepath.Join(dir, name)
			if err := os.Mkdir(parent, 0o755); err != nil {
				t.Fatal(err)
			}
			if shared {
				if err := os.Chown(parent, 0, 65533); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(parent, 0o770); err != nil {
					t.Fatal(err)
				}
			}
			vault := filepath.Join(parent, "private-vault")
			if err := os.Mkdir(vault, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(vault, "secret"), []byte("private-directory-sentinel"), 0o644); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(vault)
			if err != nil {
				t.Fatal(err)
			}
			created := filepath.Join(parent, "new")
			cmd := exec.CommandContext(ctx, bin, "mkdir", filepath.Join(created, "nested"))
			cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			pid := cmd.Process.Pid
			var wait syscall.WaitStatus
			if _, err := syscall.Wait4(pid, &wait, 0, nil); err != nil {
				t.Fatal(err)
			}
			if err := syscall.PtraceSetOptions(pid, syscall.PTRACE_O_TRACESYSGOOD); err != nil {
				t.Fatal(err)
			}
			exchanged := false
			signal := 0
			for {
				if err := syscall.PtraceSyscall(pid, signal); err != nil {
					t.Fatal(err)
				}
				if _, err := syscall.Wait4(pid, &wait, 0, nil); err != nil {
					t.Fatal(err)
				}
				if wait.Exited() {
					if wait.ExitStatus() != 0 && (!shared || exchanged) {
						t.Fatalf("creation exited %d: %s", wait.ExitStatus(), output.String())
					}
					break
				}
				if wait.Signaled() {
					t.Fatalf("creation terminated by %s", wait.Signal())
				}
				signal = 0
				if wait.StopSignal() != syscall.Signal(int(syscall.SIGTRAP)|0x80) {
					if wait.StopSignal() != syscall.SIGTRAP {
						signal = int(wait.StopSignal())
					}
					continue
				}
				var regs syscall.PtraceRegs
				if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
					t.Fatal(err)
				}
				if exchanged || regs.Orig_rax != syscall.SYS_OPENAT || int64(regs.Rax) < 0 {
					continue
				}
				opened, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", strconv.Itoa(int(regs.Rax))))
				if err != nil || opened != created {
					continue
				}
				uid, gid := uint32(0), uint32(0)
				if shared {
					uid, gid = 65533, 65533
				}
				exchange := exec.CommandContext(ctx, bin, "exchange", created, vault)
				exchange.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
				if output, err := exchange.CombinedOutput(); err != nil {
					t.Fatalf("controlled directory exchange: %v\n%s", err, output)
				}
				exchanged = true
			}
			cmd.Wait()
			private := vault
			if exchanged {
				private = created
			}
			after, err := os.Stat(private)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(before, after) || after.Mode().Perm() != 0o700 {
				t.Errorf("pathname exchange remoded the private inode: mode=%04o", after.Mode().Perm())
			}
			read := exec.CommandContext(ctx, bin, "read", filepath.Join(private, "secret"))
			read.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 65533}}
			if data, err := read.Output(); err == nil {
				t.Errorf("dropped UID read the exchanged private sentinel: %q", data)
			}
			if !shared && !exchanged {
				t.Fatal("trusted-parent fixture did not reach the descriptor exchange")
			}
		})
	}
}

func TestCustomLogLeafTraversableWithRestrictiveUmask(t *testing.T) {
	dir, bin, ctx := creationFixture(t)
	for _, path := range []string{"app", "openvpn/server/pki/private", "shared"} {
		if err := os.MkdirAll(filepath.Join(dir, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "app/.env"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(dir, "shared")
	sentinel := filepath.Join(parent, "private-sentinel")
	if err := os.WriteFile(sentinel, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(parent, "new-parent", "custom-log-leaf", "events.log")
	cmd := exec.CommandContext(ctx, bin, "repair-umask", filepath.Join(dir, "openvpn"))
	cmd.Env = append(os.Environ(), "AppDir="+filepath.Join(dir, "app"), "OpenVpnRoot="+filepath.Join(dir, "openvpn"),
		"DataDir="+filepath.Join(dir, "data"), "UsersDir="+filepath.Join(dir, "data/users"),
		"SessionsDir="+filepath.Join(dir, "data/sessions"), "UsageDir="+filepath.Join(dir, "data/usage"),
		"LogDir="+filepath.Dir(log), "LogFile="+log, "RuntimeGroup=65533")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated umask-077 repair: %v\n%s", err, output)
	}
	appendLog := exec.CommandContext(ctx, bin, "append-log", log)
	appendLog.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 65533}}
	if output, err := appendLog.CombinedOutput(); err != nil {
		t.Errorf("dropped UID cannot append through the new custom log leaf: %v\n%s", err, output)
	}
	for path, want := range map[string]os.FileMode{parent: 0o755, sentinel: 0o600, filepath.Dir(log): 0o755} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want || info.Sys().(*syscall.Stat_t).Gid != 0 {
			t.Errorf("shared parent/sentinel or new log leaf has wrong access: %s mode=%04o group=%d", path, info.Mode().Perm(), info.Sys().(*syscall.Stat_t).Gid)
		}
	}
}
