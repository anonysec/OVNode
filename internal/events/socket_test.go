// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package events

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "ovnode-events-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	usage := filepath.Join(root, "usage")
	if err := os.MkdirAll(usage, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logDir := filepath.Join(root, "log")
	vpnRoot := filepath.Join(root, "openvpn")
	if err := os.MkdirAll(filepath.Join(vpnRoot, "server", "udp"), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Join(root, "sessions"), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(
		"DataDir="+root+"\n"+
			"UsageDir="+usage+"\n"+
			"SessionsDir="+filepath.Join(root, "sessions")+"\n"+
			"LogDir="+logDir+"\n"+
			"OpenVpnRoot="+vpnRoot+"\n"+
			"LogFile="+filepath.Join(logDir, "hook-events.log")+"\n"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// .env wins over the process env, so AppDir must point at the temp dir
	// for the temp .env to be the one fsx loads.
	os.Setenv("AppDir", root)
	code := m.Run()
	os.RemoveAll(root)
	os.Exit(code)
}

// startListener spawns Listen and returns a stop that cancels it and waits
// for the goroutine to finish; safe to call more than once.
func startListener(t *testing.T, h *Hub, sessions func() (any, error)) func() {
	t.Helper()
	var once sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	resetSocketState()
	go func() { done <- Listen(ctx, h, sessions) }()
	deadline := time.Now().Add(2 * time.Second)
	for !SocketBound() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if SocketErr() != nil {
		once.Do(func() { cancel() })
		<-done
		t.Fatalf("socket did not bind: %v", SocketErr())
	}
	return func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("Listen did not return after cancel")
			}
		})
	}
}

func TestListenReceivesDatagramAndPublishes(t *testing.T) {
	h := NewHub()
	sub := h.Subscribe()
	stop := startListener(t, h, func() (any, error) { return map[string]int{"live": 1}, nil })
	defer stop()
	if err := NotifyHook("connect", "2"); err != nil {
		t.Fatalf("notify: %v", err)
	}
	var payload Payload
	select {
	case p := <-sub.C():
		payload = p
	case <-time.After(2 * time.Second):
		t.Fatal("no payload after hook datagram")
	}
	if payload.Kind != "sessions" {
		t.Fatalf("kind %q, want sessions", payload.Kind)
	}
	var body map[string]int
	if err := json.Unmarshal(payload.Data, &body); err != nil {
		t.Fatalf("snapshot body: %v", err)
	}
	if body["live"] != 1 {
		t.Fatalf("snapshot body %s", payload.Data)
	}
	stop()
	if _, err := os.Stat(SocketPath()); !os.IsNotExist(err) {
		t.Fatal("socket file left behind after stop")
	}
}

func TestSocketPerms(t *testing.T) {
	h := NewHub()
	stop := startListener(t, h, func() (any, error) { return nil, nil })
	defer stop()
	info, err := os.Stat(SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Fatalf("socket mode %o, want 660", perm)
	}
}

func TestNotifyHookMissingSocketIsSilent(t *testing.T) {
	_ = os.Remove(SocketPath())
	start := time.Now()
	if err := NotifyHook("connect", "2"); err != nil {
		t.Fatalf("missing socket returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("notify with no listener took %s", elapsed)
	}
}

func TestNotifyHookHungSocketDoesNotStall(t *testing.T) {
	// A listener bound but never reading: the datagram sits in the receive
	// queue, so the hook must still return promptly.
	h := NewHub()
	stop := startListener(t, h, func() (any, error) { return nil, nil })
	defer stop()
	start := time.Now()
	_ = NotifyHook("connect", "2")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("hook notify took %s against a full socket", elapsed)
	}
}
