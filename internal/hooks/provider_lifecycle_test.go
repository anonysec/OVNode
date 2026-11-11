// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package hooks

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ovnode/internal/ovpn"
	"ovnode/internal/pki"
	"ovnode/internal/store"
)

func TestProviderDisableAndDeletePreserveFinalBanking(t *testing.T) {
	if _, err := exec.LookPath("openvpn"); err != nil {
		t.Skip("openvpn is required")
	}
	if _, err := os.Stat("/usr/share/easy-rsa/easyrsa"); err != nil {
		t.Skip("easy-rsa is required")
	}
	for _, cid := range []string{"42", ""} {
		t.Run("cid-"+cid, func(t *testing.T) {
			tr := newTree(t)
			t.Setenv("OpenVpnRoot", filepath.Join(tr.dir, "openvpn"))
			t.Setenv("DataDir", tr.dir)
			t.Setenv("UsersDir", tr.users)
			t.Setenv("SessionsDir", tr.sessions)
			t.Setenv("UsageDir", tr.usage)
			t.Setenv("StatusFile", tr.status)
			t.Setenv("LogDir", filepath.Dir(tr.logFile))
			t.Setenv("LogFile", tr.logFile)
			t.Setenv("MgmtPassFile", filepath.Join(tr.dir, "mgmt-pass"))
			if err := ovpn.InitPKI(); err != nil {
				t.Fatal(err)
			}
			if err := ovpn.CreateUser("alice", "Alice", 3, nil); err != nil {
				t.Fatal(err)
			}
			status := "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\n" +
				"CLIENT_LIST\talice\t198.51.100.1:1000\t10.66.0.2\t\t10\t20\tfixture\t100\tUNDEF\t" + cid + "\nEND\n"
			if err := os.WriteFile(tr.status, []byte(status), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(pki.PIDFile("udp"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
				t.Fatal(err)
			}
			markerPath := filepath.Join(tr.sessions, "alice.10.66.0.2")
			if err := store.WriteMarker(markerPath, store.Marker{CommonName: "alice", PoolIP: "10.66.0.2", TrustedIP: "198.51.100.1", TrustedPort: "1000", Created: 100, SessionID: "session-alice", ConnectedAt: 100}); err != nil {
				t.Fatal(err)
			}
			sessionLock := filepath.Join(tr.sessions, ".lock.alice")
			if err := store.Lock(sessionLock, 0o660, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			if _, err := store.RecordSessionUsage(tr.usage, "alice", "session-alice", 0, false); err != nil {
				t.Fatal(err)
			}
			locks := map[string]os.FileInfo{}
			for _, path := range []string{sessionLock, filepath.Join(tr.usage, ".lock.alice")} {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				locks[path] = info
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			t.Setenv("ManagementHost", "127.0.0.1")
			t.Setenv("ManagementPort", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
			password, err := os.ReadFile(pki.MgmtPassFile())
			if err != nil {
				t.Fatal(err)
			}
			commands := make(chan string, 2)
			done := make(chan error, 1)
			go func() {
				for range 2 {
					listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					_, _ = conn.Write([]byte("ENTER PASSWORD:\n"))
					if strings.TrimSpace(readLine(conn)) != strings.TrimSpace(string(password)) {
						conn.Close()
						done <- fmt.Errorf("management password did not match")
						return
					}
					_, _ = conn.Write([]byte("SUCCESS: authenticated\n"))
					commands <- strings.TrimSpace(readLine(conn))
					_, _ = conn.Write([]byte("SUCCESS: killed\n"))
					if strings.TrimSpace(readLine(conn)) != "quit" {
						conn.Close()
						done <- fmt.Errorf("management connection did not quit")
						return
					}
					conn.Close()
				}
				done <- nil
			}()
			if err := ovpn.SetUserStatus("alice", "deactivate"); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(markerPath); err != nil {
				t.Fatalf("disable removed the final-banking marker: %v", err)
			}
			if found, err := ovpn.DeleteUser("alice"); !found || err != nil {
				t.Fatalf("delete: found=%t error=%v", found, err)
			}
			if _, err := os.Stat(markerPath); err != nil {
				t.Fatalf("delete removed the final-banking marker: %v", err)
			}
			for path, before := range locks {
				after, err := os.Stat(path)
				if err != nil || !os.SameFile(before, after) {
					t.Errorf("delete removed/replaced a final-banking lock %s: %v", path, err)
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			want := "client-kill " + cid
			if cid == "" {
				want = "kill alice"
			}
			for range 2 {
				if got := <-commands; got != want {
					t.Errorf("provider disconnect command=%q, want %q", got, want)
				}
			}
			setClientEnv(t, "alice", "10.66.0.2")
			t.Setenv("bytes_received", "25")
			t.Setenv("bytes_sent", "35")
			if code := Disconnect(tr.config(), "alice"); code != 0 {
				t.Fatalf("final disconnect failed: %d", code)
			}
			state, err := store.ReadUsageState(tr.usage, "alice")
			if err != nil || state.Total != 60 {
				t.Fatalf("final counters were not banked after deletion: %+v (%v)", state, err)
			}
			if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
				t.Fatalf("final banking did not clear its completed marker: %v", err)
			}
		})
	}
}
