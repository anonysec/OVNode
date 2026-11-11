// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package ovpn

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ovnode/internal/fsx"
	"ovnode/internal/pki"
	"ovnode/internal/store"
)

// readAllStatus merges the status snapshots of every protocol. The newest
// UpdatedAt wins; sessions are additive because each protocol has its own
// pool.
func readAllStatus() (StatusSnapshot, error) {
	combined := StatusSnapshot{Sessions: []Session{}, Complete: true}
	found := false
	for _, file := range StatusFiles() {
		snap, err := ReadStatusSnapshot(file)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return StatusSnapshot{}, err
		}
		found = true
		combined.Sessions = append(combined.Sessions, snap.Sessions...)
		if snap.UpdatedAt > combined.UpdatedAt {
			combined.UpdatedAt = snap.UpdatedAt
		}
	}
	if !found {
		return StatusSnapshot{}, os.ErrNotExist
	}
	return combined, nil
}

// UsersUsage returns the per-user traffic counters in the shape the panel
// consumes. It records each live session's observed bytes (session lock
// before usage lock) and reports totals from the authoritative persisted
// counter only — the live snapshot is never added a second time.
func UsersUsage() (map[string]any, error) {
	snap, err := readAllStatus()
	if err != nil {
		return nil, err
	}
	names := store.NameMap(pki.UsersDir())
	display := func(cn string) string {
		if name := names[cn]; name != "" {
			return name
		}
		return cn
	}
	live := liveTotals(snap.Sessions, display, names)
	present, err := reconcileLive(snap, names)
	if err != nil {
		return nil, err
	}
	totals, totalsEpochs, err := readTotals(display, present)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"users":         live.users,
		"sessions":      live.sessions,
		"totals":        totals,
		"totals_epochs": totalsEpochs,
	}, nil
}

type liveView struct {
	users    map[string]uint64
	sessions map[string]map[string]uint64
}

// liveTotals builds the per-user live snapshot views (users, sessions) the
// panel sees, keyed by display name where applicable.
func liveTotals(sessions []Session, display func(string) string, names map[string]string) liveView {
	users := map[string]uint64{}
	perSession := map[string]map[string]uint64{}
	for _, s := range sessions {
		total := s.BytesReceived + s.BytesSent
		users[s.CommonName] += total
		if perSession[s.CommonName] == nil {
			perSession[s.CommonName] = map[string]uint64{}
		}
		if _, ok := perSession[s.CommonName][s.RealAddress]; !ok || total > perSession[s.CommonName][s.RealAddress] {
			perSession[s.CommonName][s.RealAddress] = total
		}
	}
	sessionRows := map[string]map[string]uint64{}
	for cn, per := range perSession {
		sessionRows[cn] = per
		if name := names[cn]; name != "" && name != cn {
			sessionRows[name] = per
		}
	}
	liveByName := map[string]uint64{}
	for cn, total := range users {
		liveByName[display(cn)] += total
	}
	return liveView{users: liveByName, sessions: sessionRows}
}

// reconcileLive records each live session's observed bytes. The per-CN
// lock is taken only when a write is needed (bytes changed): an unchanged
// poll does not wait or write again. The returned map is the set of live
// accounting IDs per CN, extended with marker IDs for receipt retention.
func reconcileLive(snap StatusSnapshot, names map[string]string) (map[string]map[string]bool, error) {
	sessions := snap.Sessions
	byCNSession := map[string][]Session{}
	var cns []string
	for _, s := range sessions {
		if _, seen := byCNSession[s.CommonName]; !seen {
			cns = append(cns, s.CommonName)
		}
		byCNSession[s.CommonName] = append(byCNSession[s.CommonName], s)
	}
	sort.Strings(cns)
	allMarkers := readMarkers()
	byCN := map[string][]marker{}
	for _, m := range allMarkers {
		byCN[m.commonName] = append(byCN[m.commonName], m)
	}
	present := map[string]map[string]bool{}
	for _, cn := range cns {
		rows := byCNSession[cn]
		present[cn] = map[string]bool{}
		cands := byCN[cn]
		_ = cands
		type rec struct {
			sessionID string
			bytes     uint64
		}
		var recs []rec
		for _, s := range rows {
			chosen := chooseMarker(s, cands, snap.UpdatedAt)
			var sessionID string
			switch {
			case chosen != nil:
				sessionID = chosen.sessionID
			case len(cands) == 0:
				sessionID = derivedSessionID(s)
			default:
				continue
			}
			bytes := s.BytesReceived + s.BytesSent
			if needsWrite(cn, sessionID, bytes) {
				recs = append(recs, rec{sessionID, bytes})
			}
			present[cn][sessionID] = true
		}
		if len(recs) == 0 {
			continue
		}
		if err := store.Lock(filepath.Join(pki.SessionsDir(), ".lock."+cn), 0o660, func() error {
			for _, r := range recs {
				if _, err := store.RecordSessionUsage(pki.UsageDir(), cn, r.sessionID, r.bytes, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	for _, m := range allMarkers {
		if present[m.commonName] == nil {
			present[m.commonName] = map[string]bool{}
		}
		present[m.commonName][m.sessionID] = true
		present[m.commonName][m.key] = true
	}
	return present, nil
}

// needsWrite reports whether this poll should record new bytes: the stored
// session bytes differ, or the session does not exist yet. An unchanged
// session is answered by the persisted counter without opening a temp
// file or taking the per-CN lock downstream.
func needsWrite(cn, sessionID string, bytes uint64) bool {
	st, err := store.ReadUsageState(pki.UsageDir(), cn)
	if err != nil || st.Sessions == nil {
		return true
	}
	sess, ok := st.Sessions[sessionID]
	if !ok {
		return true
	}
	if sess.Closed {
		return true
	}
	return bytes > sess.Bytes
}

// readTotals loads every persisted counter and builds the totals and
// totals_epochs maps with the same contributor set. Unreadable counters
// fail the sample.
func readTotals(display func(string) string, present map[string]map[string]bool) (map[string]uint64, map[string]string, error) {
	totals := map[string]uint64{}
	epochsByCN := map[string]string{}
	entries, err := os.ReadDir(pki.UsageDir())
	if err != nil {
		return nil, nil, err
	}
	cnSet := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".lock.") {
			continue
		}
		if !fsx.StoreKeyRe.MatchString(e.Name()) {
			continue
		}
		cnSet[e.Name()] = true
	}
	var allCNs []string
	for cn := range cnSet {
		allCNs = append(allCNs, cn)
	}
	sort.Strings(allCNs)
	for _, cn := range allCNs {
		st, err := store.ReadUsageState(pki.UsageDir(), cn)
		if err != nil {
			return nil, nil, err
		}
		totals[display(cn)] += st.Total
		epochsByCN[cn] = st.Epoch
	}
	for _, cn := range allCNs {
		if err := store.PruneReceipts(pki.UsageDir(), cn, present[cn]); err != nil {
			return nil, nil, err
		}
	}
	totalsEpochs := map[string]string{}
	byName := map[string][]string{}
	for _, cn := range allCNs {
		byName[display(cn)] = append(byName[display(cn)], cn)
	}
	for name, cns := range byName {
		if len(cns) == 1 {
			totalsEpochs[name] = epochsByCN[cns[0]]
			continue
		}
		sort.Strings(cns)
		pairs := make([]string, 0, len(cns))
		for _, cn := range cns {
			pairs = append(pairs, cn+"="+epochsByCN[cn])
		}
		totalsEpochs[name] = strings.Join(pairs, ",")
	}
	for name := range totals {
		if _, ok := totalsEpochs[name]; !ok {
			totalsEpochs[name] = ""
		}
	}
	return totals, totalsEpochs, nil
}

// chooseMarker picks the marker generation that may account for a status
// row. A marker created at/after the snapshot time cannot be the row's
// generation (the snapshot predates it); pool identity decides otherwise.
func chooseMarker(s Session, cands []marker, updatedAt int64) *marker {
	var chosen *marker
	for i := range cands {
		mk := &cands[i]
		ts := mk.connectedAt
		if ts == 0 {
			ts = mk.created
		}
		if updatedAt > 0 && ts > 0 && updatedAt <= ts {
			continue
		}
		if mk.poolIP != "" && mk.poolIP != s.VirtualAddress {
			continue
		}
		if mk.poolIP == "" {
			if mk.trustedIP != s.TrustedIP || mk.trustedPort != s.TrustedPort {
				continue
			}
		}
		if chosen == nil {
			tmp := *mk
			chosen = &tmp
			continue
		}
		chosenTS := chosen.connectedAt
		if chosenTS == 0 {
			chosenTS = chosen.created
		}
		if ts > chosenTS {
			tmp := *mk
			chosen = &tmp
		}
	}
	return chosen
}

// derivedSessionID is the stable accounting identity of a markerless live
// session, from the full observed status row.
func derivedSessionID(s Session) string {
	return fmt.Sprintf("%s.%s.%s.%d", s.CommonName, s.VirtualAddress, s.ClientID, s.ConnectedAt)
}
