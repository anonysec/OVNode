// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"ovnode/internal/logging"
	"ovnode/internal/pki"
)

// SuperviseOpenVPN runs the OpenVPN daemon as a child of the agent process.
//
// Before there were two units (ovnode.service + ovnode-openvpn.service); both
// pointed at the same tree and both had to be restarted together. Now
// ovnode.service forks openvpn as a child and respawns it on exit — a single
// unit owns the whole lifecycle. Returns true when a config exists and the
// child was started; false otherwise.
func SuperviseOpenVPN(ctx context.Context) bool {
	conf := settingFile()
	if _, err := exec.LookPath("openvpn"); err != nil {
		return false
	}
	if _, err := os.Stat(conf); err != nil {
		return false
	}
	if !pki.IsInstalledTree() {
		return false
	}
	go supervise(ctx, conf)
	return true
}

type logLineWriter struct{ buf strings.Builder }

func (w *logLineWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	for {
		s := w.buf.String()
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(s[:i], "\r")
		if line != "" {
			logging.Info("openvpn: %s", line)
		}
		w.buf.Reset()
		w.buf.WriteString(s[i+1:])
	}
	return len(p), nil
}

func supervise(ctx context.Context, conf string) {
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		started := time.Now()
		cmd := exec.CommandContext(ctx, "openvpn", "--config", conf)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
		lw := &logLineWriter{}
		cmd.Stdout = io.MultiWriter(lw, io.Discard)
		cmd.Stderr = lw
		if err := cmd.Run(); err != nil {
			logging.Warn("openvpn child exited: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if time.Since(started) > 5*time.Minute {
			backoff = time.Second
		} else {
			backoff *= 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
		}
		logging.Info("respawning openvpn")
	}
}
