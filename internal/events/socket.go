// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package events

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ovnode/internal/fsx"
	"ovnode/internal/logging"
	"ovnode/internal/ovpn"
)

// datagramDeadline caps one hook notify so a stalled agent can never slow a
// VPN connect: the hook is fire-and-forget.
const datagramDeadline = 100 * time.Millisecond

// SocketPath is the hook→agent notify socket, inside the data dir (the
// systemd unit already allows AF_UNIX and /var/lib/ovnode).
func SocketPath() string {
	return filepath.Join(fsx.OVNodeDir(), "events.sock")
}

// socketErrState surfaces the bind failure for tests and one-time logging.
var (
	socketErrMu   sync.Mutex
	socketErrLast error
	socketBound   bool
)

// SocketErr returns the last bind error, nil once bound.
func SocketErr() error {
	socketErrMu.Lock()
	defer socketErrMu.Unlock()
	return socketErrLast
}

// SocketBound reports whether the notify socket is listening.
func SocketBound() bool {
	socketErrMu.Lock()
	defer socketErrMu.Unlock()
	return socketBound
}

func setSocketErr(err error) {
	socketErrMu.Lock()
	if err != nil {
		socketErrLast = err
		socketBound = false
	} else {
		socketBound = true
	}
	socketErrMu.Unlock()
}

func resetSocketState() {
	socketErrMu.Lock()
	socketErrLast = nil
	socketBound = false
	socketErrMu.Unlock()
}

// Listen binds the datagram socket and publishes a fresh sessions snapshot
// per datagram. Bind failure is not fatal: the agent runs without push and
// the panel falls back to polling. sessions is the snapshot provider, kept a
// parameter so the events package never imports httpapi.
func Listen(ctx context.Context, h *Hub, sessions func() (any, error)) error {
	resetSocketState()
	path := SocketPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		setSocketErr(err)
		logging.Warn("events: socket dir: %v", err)
		return nil
	}
	_ = os.Remove(path)
	addr := &net.UnixAddr{Name: path, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		setSocketErr(err)
		logging.Warn("events: push disabled, %v", err)
		return nil
	}
	setSocketErr(nil)
	if err := os.Chmod(path, 0o660); err != nil {
		logging.Warn("events: socket chmod: %v", err)
	}
	if gid := vpnGroupGID(); gid > 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			logging.Warn("events: socket chown: %v", err)
		}
	}
	defer func() {
		conn.Close()
		_ = os.Remove(path)
	}()

	buf := make([]byte, 512)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			return nil
		}
		n, _, err := conn.ReadFromUnix(buf)
		if err != nil {
			if oe, ok := err.(*net.OpError); ok && oe.Timeout() {
				select {
				case <-ctx.Done():
					return nil
				default:
				}
				continue
			}
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return nil
		}
		if n > 0 {
			var poke struct {
				Op    string `json:"op"`
				CN    string `json:"cn"`
				CID   string `json:"cid"`
				Proto string `json:"proto"`
			}
			_ = json.Unmarshal(buf[:n], &poke)
			logging.Event(fsx.LogFile(), "events: hook poke op=%s cn=%s cid=%s", poke.Op, poke.CN, poke.CID)
			if poke.CID != "" {
				go runKill(poke.CID, poke.Proto)
			}
			snap, serr := sessions()
			if serr == nil && snap != nil {
				h.Publish("sessions", snap)
			}
		}
	}
}

// NotifyHook sends one best-effort datagram. Any failure is silent by
// design: a hook must never wait on the agent or change its exit code.
func NotifyHook(op, cn string) error {
	body, _ := json.Marshal(map[string]string{"op": op, "cn": cn})
	return send(body)
}

// NotifyKill queues a targeted management kill in the agent. The hook never
// touches the single management slot itself: the agent owns that socket, can
// retry, and cannot turn a transient hold into AUTH_FAILED.
func NotifyKill(cid, proto string) error {
	body, _ := json.Marshal(map[string]string{"op": "kill", "cid": cid, "proto": proto})
	return send(body)
}

func send(body []byte) error {
	conn, err := net.DialTimeout("unixgram", SocketPath(), datagramDeadline)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(datagramDeadline))
	_, _ = conn.Write(body)
	return nil
}

// killSession is the management call the agent makes for a queued kill. Tests
// replace it to avoid a live socket.
var killSession = ovpn.SendCommandsToProtocol

// runKill retries a queued targeted kill. The management interface serves one
// client at a time, so a busy slot is normal and not a reason to lose the
// replacement.
func runKill(cid, proto string) {
	for attempt := 0; attempt < 3; attempt++ {
		var (
			replies []string
			err     error
		)
		if proto == "" {
			replies, err = ovpn.SendCommands([]string{"client-kill " + cid})
		} else {
			replies, err = killSession(proto, []string{"client-kill " + cid})
		}
		if err == nil {
			for _, reply := range replies {
				if strings.Contains(strings.ToUpper(reply), "SUCCESS") {
					logging.Event(fsx.LogFile(), "events: kill cid=%s proto=%s ok", cid, proto)
					return
				}
			}
		}
		if attempt < 2 {
			time.Sleep(time.Second)
		}
	}
	logging.Event(fsx.LogFile(), "events: kill cid=%s proto=%s failed", cid, proto)
}

// vpnGroupGID resolves the ovnode-vpn group; 0 when absent (tests, docker).
func vpnGroupGID() int {
	g, err := user.LookupGroup("ovnode-vpn")
	if err != nil {
		return 0
	}
	var gid int
	if _, err := fmt.Sscanf(g.Gid, "%d", &gid); err != nil {
		return 0
	}
	if gid <= 0 || gid >= 1<<31 {
		return 0
	}
	return int(gid)
}
