// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package fsx

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPermissionTransitionNeverGrantsWritableDescriptor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required for controlled group transition")
	}
	dir, err := os.MkdirTemp("", "ovnode-transition-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "permission-helper")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./testdata/permission-transition")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("transition fixture build: %v\n%s", err, output)
	}
	for _, mode := range []string{"transition", "repair"} {
		t.Run(mode, func(t *testing.T) {
			root := filepath.Join(dir, mode)
			for _, path := range []string{"app", "openvpn/server/pki/private", "openvpn/limits", "openvpn/ovnode/users/alice", "logs"} {
				if err := os.MkdirAll(filepath.Join(root, path), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(root, "app/.env"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			policy := filepath.Join(root, "openvpn/limits/alice")
			if err := os.WriteFile(policy, []byte("7\n"), 0o660); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(policy, 0o660); err != nil {
				t.Fatal(err)
			}
			argument := policy
			if mode == "repair" {
				argument = filepath.Join(root, "openvpn")
			}
			cmd := exec.CommandContext(ctx, bin, mode, argument)
			cmd.Env = append(os.Environ(), "OVN_APP_DIR="+filepath.Join(root, "app"), "OVNODE_OPENVPN_ROOT="+filepath.Join(root, "openvpn"),
				"OVNODE_DATA_DIR="+filepath.Join(root, "data"), "OVNODE_USERS_DIR="+filepath.Join(root, "openvpn/ovnode/users"),
				"OVNODE_SESSIONS_DIR="+filepath.Join(root, "data/sessions"), "OVNODE_USAGE_DIR="+filepath.Join(root, "data/usage"),
				"OVNODE_LOG_DIR="+filepath.Join(root, "logs"), "OVNODE_LOG_FILE="+filepath.Join(root, "logs/events.log"), "OVNODE_RUNTIME_GROUP=65533")
			cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
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
			var probe *exec.Cmd
			var ready, proceed *os.File
			var reader *bufio.Reader
			opened, observed := false, false
			signal := 0
			for {
				if err := syscall.PtraceSyscall(pid, signal); err != nil {
					t.Fatal(err)
				}
				if _, err := syscall.Wait4(pid, &wait, 0, nil); err != nil {
					t.Fatal(err)
				}
				if wait.Exited() {
					if wait.ExitStatus() != 0 {
						t.Fatalf("transition exited %d", wait.ExitStatus())
					}
					break
				}
				if wait.Signaled() {
					t.Fatalf("transition terminated by %s", wait.Signal())
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
				if observed || regs.Orig_rax != syscall.SYS_FCHOWN || regs.Rax != 0 {
					continue
				}
				path, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", strconv.Itoa(int(regs.Rdi))))
				if err != nil || path != policy {
					continue
				}
				observed = true
				status, statusWrite, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				resume, resumeWrite, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer status.Close()
				defer statusWrite.Close()
				defer resume.Close()
				defer resumeWrite.Close()
				ready, proceed = status, resumeWrite
				ready.SetReadDeadline(time.Now().Add(5 * time.Second))
				probe = exec.CommandContext(ctx, bin, "probe", policy)
				probe.ExtraFiles = []*os.File{statusWrite, resume}
				probe.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 65533}}
				if err := probe.Start(); err != nil {
					t.Fatal(err)
				}
				reader = bufio.NewReader(ready)
				message, err := reader.ReadString('\n')
				if err != nil {
					t.Fatal(err)
				}
				opened = strings.TrimSpace(message) == "opened"
				if opened {
					t.Error("new runtime group acquired a writable policy descriptor during ownership transition")
				}
			}
			cmd.Wait()
			if !observed {
				t.Fatal("controlled fixture did not observe the target group transition")
			}
			if opened {
				finalPath := policy
				if mode == "repair" {
					finalPath = filepath.Join(root, "openvpn/ovnode/users/alice/limit")
				}
				info, err := os.Stat(finalPath)
				if err != nil || info.Mode().Perm() != 0o640 {
					t.Fatalf("final policy mode must already be restrictive: %v (%v)", info, err)
				}
				if _, err := proceed.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
				if message, err := reader.ReadString('\n'); err != nil || !strings.Contains(message, "wrote after final mode") {
					t.Fatalf("descriptor completion: %q (%v)", message, err)
				}
				t.Log("runtime descriptor remained writable after final policy mode became 0640")
			}
			if err := probe.Wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
