// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package store

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"ovnode/internal/fsx"
	"ovnode/internal/logging"
)

func runtimeChild(t *testing.T, dir, name string, env ...string) (*exec.Cmd, *os.File, *os.File) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	exe = filepath.Join(dir, "runtime-child")
	if err := os.WriteFile(exe, data, 0o755); err != nil {
		t.Fatal(err)
	}
	ready, status, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	resume, proceed, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ready.Close(); status.Close(); resume.Close(); proceed.Close() })
	if err := ready.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, exe, "-test.run=^"+name+"$")
	cmd.Env = append(os.Environ(), env...)
	cmd.ExtraFiles = []*os.File{status, resume}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 65533}}
	return cmd, ready, proceed
}

func TestRuntimeAtomicWriterProcess(t *testing.T) {
	dir := os.Getenv("TestATOMIC_DIR")
	if dir == "" {
		return
	}
	status := os.NewFile(3, "status")
	resume := os.NewFile(4, "resume")
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("before repair"); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(status, f.Name())
	var byte [1]byte
	if _, err := resume.Read(byte[:]); err != nil {
		t.Fatal(err)
	}
	if err := f.Chmod(0o660); err != nil {
		t.Fatalf("repair revoked the active atomic writer's descriptor: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.Name(), filepath.Join(dir, "completed")); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRepairPreservesActiveAtomicWriter(t *testing.T) {
	dir := runtimeRepairFixture(t)
	if err := os.Chmod(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	sessions := filepath.Join(dir, "data", "sessions")
	if err := os.Chown(sessions, 0, 65533); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sessions, 0o770|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	writer, ready, proceed := runtimeChild(t, dir, "TestRuntimeAtomicWriterProcess", "TestATOMIC_DIR="+sessions)
	var writerOutput bytes.Buffer
	writer.Stdout, writer.Stderr = &writerOutput, &writerOutput
	if err := writer.Start(); err != nil {
		t.Fatal(err)
	}
	path, err := bufio.NewReader(ready).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	path = strings.TrimSpace(path)
	if output, err := repairInJail(t, dir); err != nil {
		t.Errorf("repair during active write: %v\n%s", err, output)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Sys().(*syscall.Stat_t).Uid != 65533 || info.Mode().Perm() != 0o600 {
		t.Errorf("active temporary was re-owned/remoded: owner=%d mode=%04o", info.Sys().(*syscall.Stat_t).Uid, info.Mode().Perm())
	}
	if _, err := proceed.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Wait(); err != nil {
		t.Fatalf("dropped-UID atomic completion: %v\n%s", err, writerOutput.String())
	}
}

func TestRuntimeMarkerRemovalProcess(t *testing.T) {
	path := os.Getenv("TestREMOVE_MARKER")
	if path == "" {
		return
	}
	status := os.NewFile(3, "status")
	resume := os.NewFile(4, "resume")
	fmt.Fprintln(status, "ready")
	var byte [1]byte
	if _, err := resume.Read(byte[:]); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(status, "removed")
}

func TestRuntimeRepairToleratesMarkerDisappearance(t *testing.T) {
	dir := runtimeRepairFixture(t)
	sessions := filepath.Join(dir, "data", "sessions")
	if err := os.Chown(sessions, 0, 65533); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sessions, 0o770|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	for i := range 2000 {
		if err := os.WriteFile(filepath.Join(sessions, fmt.Sprintf("a%04d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(sessions, "zz-disappearing-marker")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	remover, ready, proceed := runtimeChild(t, dir, "TestRuntimeMarkerRemovalProcess", "TestREMOVE_MARKER="+marker)
	var removeOutput bytes.Buffer
	remover.Stdout, remover.Stderr = &removeOutput, &removeOutput
	if err := remover.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(ready)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if _, err := syscall.InotifyAddWatch(fd, sessions, syscall.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	repair := repairCommand(t, dir)
	var output bytes.Buffer
	repair.Stdout, repair.Stderr = &output, &output
	if err := repair.Start(); err != nil {
		t.Fatal(err)
	}
	notified := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var events [4096]byte
		n, err := syscall.Read(fd, events[:])
		if err != nil && err != syscall.EAGAIN && err != syscall.EINTR {
			t.Fatal(err)
		}
		if n > 0 && bytes.Contains(events[:n], []byte("a0000")) {
			notified = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !notified {
		t.Fatal("repair did not reach the controlled directory-snapshot interleaving")
	}
	if _, err := proceed.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if err := remover.Wait(); err != nil {
		t.Fatalf("runtime marker removal: %v\n%s", err, removeOutput.String())
	}
	if err := repair.Wait(); err != nil {
		t.Fatalf("legitimate marker disappearance aborted repair: %v\n%s", err, output.String())
	}
}

func TestNestedRuntimeRepairProcess(t *testing.T) {
	jail := os.Getenv("TestNESTED_JAIL")
	if jail == "" {
		return
	}
	if err := syscall.Chroot(jail); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("/"); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"OpenVpnRoot": "/openvpn", "DataDir": "/relocated/one/node", "UsersDir": "/relocated/one/node/policies/by-cn",
		"SessionsDir": "/shared/markers/current", "UsageDir": "/ledger/usage/current",
		"LogDir": "/new-logs/a/b", "LogFile": "/new-logs/a/b/events.log", "RuntimeGroup": "65533",
	} {
		t.Setenv(key, value)
	}
	if err := FixRuntimePermissions("/openvpn"); err != nil {
		t.Fatal(err)
	}
	if err := SetLimit(fsx.UsersDir(), "alice", 2); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fsx.UsersDir(), "alice", "key.pem"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNestedRuntimeAccessProcess(t *testing.T) {
	dir := os.Getenv("TestNESTED_ACCESS")
	if dir == "" {
		return
	}
	users := filepath.Join(dir, "relocated/one/node/policies/by-cn")
	if st, err := ReadUserState(users, "alice"); err != nil || st.Limit != 2 {
		t.Errorf("nested policy read: %+v (%v)", st, err)
	}
	sessions := filepath.Join(dir, "shared/markers/current")
	if err := Lock(filepath.Join(sessions, ".lock.alice"), 0o660, func() error {
		return WriteMarker(filepath.Join(sessions, "alice.10.66.0.2"), Marker{CommonName: "alice"})
	}); err != nil {
		t.Errorf("nested session write: %v", err)
	}
	if _, err := RecordSessionUsage(filepath.Join(dir, "ledger/usage/current"), "alice", "nested", 5, true); err != nil {
		t.Errorf("nested usage write: %v", err)
	}
	log := filepath.Join(dir, "new-logs/a/b/events.log")
	logging.Event(log, "nested runtime event")
	if data, err := os.ReadFile(log); err != nil || !bytes.Contains(data, []byte("nested runtime event")) {
		t.Errorf("nested log append: %q (%v)", data, err)
	}
	if _, err := os.ReadFile(filepath.Join(users, "alice", "key.pem")); err == nil {
		t.Error("nested traversal exposed a private key")
	}
}

func TestRuntimePermissionsCreateTraversableNestedParents(t *testing.T) {
	dir := runtimeRepairFixture(t)
	shared := filepath.Join(dir, "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	repair := exec.CommandContext(ctx, exe, "-test.run=^TestNestedRuntimeRepairProcess$")
	repair.Env = append(os.Environ(), "TestNESTED_JAIL="+dir)
	if output, err := repair.CombinedOutput(); err != nil {
		t.Fatalf("nested repair: %v\n%s", err, output)
	}
	probe, _, _ := runtimeChild(t, dir, "TestNestedRuntimeAccessProcess", "TestNESTED_ACCESS="+dir)
	if output, err := probe.CombinedOutput(); err != nil {
		t.Errorf("configured UID cannot traverse newly-created parents: %v\n%s", err, output)
	}
	info, err := os.Stat(shared)
	if err != nil || info.Mode().Perm() != 0o755 || info.Sys().(*syscall.Stat_t).Gid != 0 {
		t.Fatalf("existing unrelated parent was changed: %v (%v)", info, err)
	}
}
