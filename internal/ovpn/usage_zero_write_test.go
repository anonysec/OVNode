// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"ovnode/internal/pki"
)

// countWrites counts atomic renames into dir by watching the usage files.
// The second poll with unchanged bytes must not write.
func countWrites(t *testing.T, dir string, fn func()) int {
	t.Helper()
	before := map[string]os.FileInfo{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		fi, err := os.Stat(filepath.Join(dir, e.Name()))
		if err == nil {
			before[e.Name()] = fi
		}
	}
	fn()
	entries, _ = os.ReadDir(dir)
	writes := 0
	for _, e := range entries {
		fi, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		prev := before[e.Name()]
		if prev == nil {
			writes++
			continue
		}
		if !fi.ModTime().Equal(prev.ModTime()) || fi.Size() != prev.Size() {
			writes++
		}
	}
	return writes
}

func TestUsersUsageUnchangedBytesPerformsZeroWrites(t *testing.T) {
	accountingTree(t)
	body := "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\n" +
		"CLIENT_LIST\talice\t198.51.100.1:1000\t10.66.0.2\t\t50\t0\tfixture\t100\tUNDEF\t1\t0\nEND\n"
	accountingStatus(t, body)
	if _, err := UsersUsage(); err != nil {
		t.Fatal(err)
	}
	if _, err := UsersUsage(); err != nil {
		t.Fatal(err)
	}
	writes := countWrites(t, pki.UsageDir(), func() {
		if _, err := UsersUsage(); err != nil {
			t.Fatal(err)
		}
	})
	if writes != 0 {
		t.Fatalf("second poll with unchanged bytes wrote %d usage files, want 0", writes)
	}
}

func TestUsersUsageChangedBytesWrites(t *testing.T) {
	accountingTree(t)
	body := "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\n" +
		"CLIENT_LIST\talice\t198.51.100.1:1000\t10.66.0.2\t\t50\t0\tfixture\t100\tUNDEF\t1\t0\nEND\n"
	accountingStatus(t, body)
	if _, err := UsersUsage(); err != nil {
		t.Fatal(err)
	}
	body2 := "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\n" +
		"CLIENT_LIST\talice\t198.51.100.1:1000\t10.66.0.2\t\t60\t0\tfixture\t100\tUNDEF\t1\t0\nEND\n"
	accountingStatus(t, body2)
	time.Sleep(10 * time.Millisecond)
	writes := countWrites(t, pki.UsageDir(), func() {
		if _, err := UsersUsage(); err != nil {
			t.Fatal(err)
		}
	})
	if writes == 0 {
		t.Fatalf("poll with changed bytes wrote 0 files, want >0")
	}
	// totals still reflect the changed snapshot
	usage, err := UsersUsage()
	if err != nil {
		t.Fatal(err)
	}
	if totals, ok := usage["totals"].(map[string]uint64); !ok || totals["alice"] != 60 {
		t.Fatalf("totals = %v, want alice=60", usage["totals"])
	}
}
