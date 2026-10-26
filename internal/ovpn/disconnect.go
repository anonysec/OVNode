// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"os"
	"path/filepath"
	"strings"

	"ovnode/internal/pki"
)

// DisconnectUser drops a user's sessions and reports what it did.
//
// only_stale is the safe mode: it never kills a live session, it only drops
// the markers whose session is gone. A user who also holds a healthy session
// must not be disconnected by a stale-marker sweep, and a live session must
// never be killed because of a marker.
func DisconnectUser(cn string, onlyStale bool) (removed []string, killed int, mgmt map[string]any) {
	sessions := ParseSessions(StatusFile())
	idx := newLiveIndex(sessions)

	killOK := false
	mgmt = map[string]any{"available": nil, "ok": nil, "skipped": "only_stale"}
	if !onlyStale {
		if !TreeOpenVPNRunning() {
			// The tree's OpenVPN is not running: there is nothing to kill
			// and the socket on the port may belong to another tree.
			mgmt = map[string]any{"available": false, "ok": false, "skipped": "openvpn not running"}
		} else {
			killed, killOK = killSessions(cn, sessions)
			mgmt = map[string]any{"available": true, "ok": killOK, "killed_sessions": killed}
		}
	}

	for _, m := range readMarkers() {
		if m.commonName != cn {
			continue
		}
		// A succeeded kill or a dead marker: either way the marker goes.
		if !killOK && m.isLive(idx) {
			continue
		}
		path := filepath.Join(pki.SessionsDir(), m.key)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			continue
		}
		removed = append(removed, m.key)
	}
	return removed, killed, mgmt
}

// killSessions kills the live sessions of a common name over the management
// socket.
//
// client-kill <CID> targets the exact session regardless of the client's
// current address; kill <cn> is the fallback for a status file that carries
// no client id.
func killSessions(cn string, sessions []Session) (int, bool) {
	var cids []string
	for _, s := range sessions {
		if s.CommonName == cn && isDigits(s.ClientID) {
			cids = append(cids, s.ClientID)
		}
	}
	if len(cids) == 0 {
		replies, err := SendCommands([]string{"kill " + cn})
		if err != nil {
			return 0, false
		}
		return 0, replyOK(replies)
	}
	cmds := make([]string, 0, len(cids))
	for _, cid := range cids {
		cmds = append(cmds, "client-kill "+cid)
	}
	replies, err := SendCommands(cmds)
	if err != nil {
		return 0, false
	}
	killed := 0
	for _, r := range replies {
		if replyOK([]string{r}) {
			killed++
		}
	}
	return killed, killed == len(cids)
}

// replyOK reports whether a management reply says SUCCESS.
func replyOK(replies []string) bool {
	for _, r := range replies {
		if !strings.Contains(strings.ToUpper(r), "SUCCESS") {
			return false
		}
	}
	return len(replies) > 0
}

// isDigits reports whether a string is a non-empty run of digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
