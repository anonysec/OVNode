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

// UsersUsage returns the per-user traffic counters in the shape the panel
// consumes. It records each live session's observed bytes (session lock
// before usage lock) and reports totals from the authoritative persisted
// counter only — the live snapshot is never added a second time.
func UsersUsage() (map[string]any, error) {
	snap, err := ReadStatusSnapshot(StatusFile())
	if err != nil {
		return nil, err
	}
	sessions := snap.Sessions

	names := store.NameMap(pki.UsersDir())
	display := func(cn string) string {
		if name := names[cn]; name != "" {
			return name
		}
		return cn
	}

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

	// Group live rows by CN; identity check and recording run under the
	// per-CN session lock (session lock before usage lock).
	byCNSession := map[string][]Session{}
	var cns []string
	for _, s := range sessions {
		if _, seen := byCNSession[s.CommonName]; !seen {
			cns = append(cns, s.CommonName)
		}
		byCNSession[s.CommonName] = append(byCNSession[s.CommonName], s)
	}
	sort.Strings(cns)
	present := map[string]map[string]bool{} // cn -> live accounting IDs
	for _, cn := range cns {
		rows := byCNSession[cn]
		present[cn] = map[string]bool{}
		err := store.Lock(filepath.Join(pki.SessionsDir(), ".lock."+cn), 0o660, func() error {
			markers := readMarkers()
			var cands []marker
			for _, m := range markers {
				if m.commonName == cn {
					cands = append(cands, m)
				}
			}
			for _, s := range rows {
				chosen := chooseMarker(s, cands, snap.UpdatedAt)
				var sessionID string
				switch {
				case chosen != nil:
					sessionID = chosen.sessionID
				case len(cands) == 0:
					// Markerless live legacy session: derive a stable ID
					// from the complete observed status identity so
					// repeated polls keep one offset and never rebase.
					sessionID = derivedSessionID(s)
				default:
					// Markers exist but none match this row (e.g. a stale
					// snapshot): never fall back to another candidate.
					continue
				}
				bytes := s.BytesReceived + s.BytesSent
				if _, err := store.RecordSessionUsage(pki.UsageDir(), cn, sessionID, bytes, false); err != nil {
					return err
				}
				present[cn][sessionID] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
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

	// Totals from the persisted counter. Any unreadable counter fails the
	// sample: a corrupt file must not report as partial success or zero.
	totals := map[string]uint64{}
	epochsByCN := map[string]string{}
	entries, err := os.ReadDir(pki.UsageDir())
	if err != nil {
		return nil, err
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
	// Only persisted counters contribute to totals. A live session with no
	// counter file must not mint a fresh epoch per poll (ReadUsageState
	// fabricates one) — the panel reseeds on epoch change and drops bytes.
	// Marker session IDs count as present for receipt retention.
	markers := readMarkers()
	for _, m := range markers {
		if present[m.commonName] == nil {
			present[m.commonName] = map[string]bool{}
		}
		present[m.commonName][m.sessionID] = true
		present[m.commonName][m.key] = true
	}
	var allCNs []string
	for cn := range cnSet {
		allCNs = append(allCNs, cn)
	}
	sort.Strings(allCNs)
	for _, cn := range allCNs {
		st, err := store.ReadUsageState(pki.UsageDir(), cn)
		if err != nil {
			return nil, err
		}
		totals[display(cn)] += st.Total
		epochsByCN[cn] = st.Epoch
	}
	// Retire completed receipts whose generation is confirmed gone.
	for _, cn := range allCNs {
		if err := store.PruneReceipts(pki.UsageDir(), cn, present[cn]); err != nil {
			return nil, err
		}
	}

	// totals and totals_epochs share the same complete contributor set.
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

	return map[string]any{
		"users":         liveByName,
		"sessions":      sessionRows,
		"totals":        totals,
		"totals_epochs": totalsEpochs,
	}, nil
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
