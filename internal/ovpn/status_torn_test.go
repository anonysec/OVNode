// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A read that lands in OpenVPN's truncate+rewrite window has no END line.
// Admission must re-read rather than take the partial list for no sessions.
func TestParseSessionsRetriesATornRead(t *testing.T) {
	old := statusRetryPause
	statusRetryPause = 100 * time.Millisecond
	t.Cleanup(func() { statusRetryPause = old })

	dir := t.TempDir()
	path := filepath.Join(dir, "status.log")
	header := "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID\n"
	row := "CLIENT_LIST,u1,9.9.9.9:5001,10.8.0.2,,,,0,0,,,,42,0\n"
	if err := os.WriteFile(path, []byte(header+row), 0o644); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(path, []byte(header+row+"END\n"), 0o644)
	}()

	got := ParseSessions(path)
	if len(got) != 1 {
		t.Fatalf("sessions = %d, want 1 after the retry", len(got))
	}
}
