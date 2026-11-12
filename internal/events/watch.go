// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package events

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ovnode/internal/fsx"
	"ovnode/internal/ovpn"
)

const (
	usageEveryTicks     = 10
	heartbeatEveryTicks = 20
)

// Watch turns local state changes into hub payloads. One cheap stat pass per
// tick, and everything is skipped while no stream consumer is attached: a
// fresh consumer always receives a full snapshot on connect, so nothing is
// lost while the watcher idles.
func Watch(ctx context.Context, h *Hub, tick time.Duration, sessions func() (any, error)) {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	last := ""
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		n++
		if h.Count() == 0 {
			continue
		}
		if fp := fingerprint(); fp != last {
			last = fp
			if snap, err := sessions(); err == nil && snap != nil {
				h.Publish("sessions", snap)
			}
		}
		if n%usageEveryTicks == 0 {
			if totals, err := ovpn.PersistedTotals(); err == nil {
				h.Publish("usage", map[string]any{"totals": totals})
			}
		}
		if n%heartbeatEveryTicks == 0 {
			h.Publish("heartbeat", nil)
		}
	}
}

// fingerprint hashes what a session change touches: the status files and the
// marker files in the sessions dir. Names, sizes and mtimes only — reading
// the status body is the snapshot provider's job.
func fingerprint() string {
	var sb strings.Builder
	for _, f := range ovpn.StatusFiles() {
		stamp(&sb, f)
	}
	entries, err := os.ReadDir(fsx.SessionsDir())
	if err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".lock.") {
				continue
			}
			stamp(&sb, filepath.Join(fsx.SessionsDir(), e.Name()))
		}
	}
	return sb.String()
}

func stamp(sb *strings.Builder, path string) {
	if st, err := os.Stat(path); err == nil {
		fmt.Fprintf(sb, "%s:%d:%d;", path, st.ModTime().UnixNano(), st.Size())
	}
}
