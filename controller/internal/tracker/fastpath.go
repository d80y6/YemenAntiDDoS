package tracker

import (
	"log"
	"net"
	"time"
)

// CriticalSignal is the Controller-side view of a Node CriticalEvent. It is
// deliberately protobuf-free so the tracker stays decoupled from the wire
// format; the ingestion layer adapts pb.CriticalEvent into this struct.
//
// The signal drives the sub-second autonomous path: instead of waiting for
// the next 1s StatsStream tick to confirm an attack, the Controller escalates
// the attack to Active immediately (<200ms) and the action engine pushes a
// broad inline mitigation rule right away — phase 1 of narrow-then-rebreadth.
type CriticalSignal struct {
	NodeID     string
	TargetIP   net.IP
	Decoder    string
	EventType  string // "burst_emergency", "hard_threshold_exceeded", …
	AttackType string
	CurrentPPS uint64
	CurrentBPS uint64
	At         time.Time // zero = now
}

// FastTrackConfirm escalates a CriticalSignal to an Active attack immediately,
// bypassing the consecutive-tick confirmation window.
//
//   - new key            → created and promoted to Active now ("confirmed")
//   - confirming         → promoted to Active now
//   - expiring           → re-activated (rebreach callback fired)
//   - active             → refreshed (peaks/last-seen), no duplicate event
//
// Returns the attack DB id and whether this call emitted a "confirmed" event.
func (t *Tracker) FastTrackConfirm(sig CriticalSignal) (int, bool) {
	if sig.TargetIP == nil {
		return 0, false
	}
	at := sig.At
	if at.IsZero() {
		at = time.Now()
	}
	decoder := sig.Decoder
	if decoder == "" {
		decoder = "ip"
	}

	key := attackKey{
		DstIP:         canonicalHostKey(sig.TargetIP.String()),
		Direction:     "receives",
		DecoderFamily: decoder,
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	a, exists := t.attacks[key]
	if exists {
		a.LastSeen = at
		a.SeenThisTick = true
		if int64(sig.CurrentPPS) > a.PeakPPS {
			a.PeakPPS = int64(sig.CurrentPPS)
		}
		if int64(sig.CurrentBPS) > a.PeakBPS {
			a.PeakBPS = int64(sig.CurrentBPS)
		}
		a.CurrentPPS = int64(sig.CurrentPPS)
		a.CurrentBPS = int64(sig.CurrentBPS)
		if a.AttackType == "" {
			a.AttackType = sig.AttackType
		}
		if sig.NodeID != "" && !containsString(a.NodeSources, sig.NodeID) {
			a.NodeSources = append(a.NodeSources, sig.NodeID)
			t.markRing(a, sig.NodeID)
		}

		switch a.State {
		case StateActive:
			return a.DBID, false
		case StateExpiring:
			a.State = StateActive
			a.ExpiresAt = time.Time{}
			log.Printf("tracker: fast-path re-activated %s/%s (node=%s pps=%d)",
				a.Key.DstIP, a.Key.DecoderFamily, sig.NodeID, a.PeakPPS)
			if t.onRebreach != nil && a.DBID > 0 {
				t.onRebreach(a.DBID)
			}
			return a.DBID, false
		case StateConfirming:
			t.transitionToActive(a, at)
			return a.DBID, a.State == StateActive
		default:
			return a.DBID, false
		}
	}

	// Brand-new key: bypass the confirmation window entirely.
	a = &trackedAttack{
		Key:              key,
		State:            StateConfirming,
		ConfirmThreshold: 1,
		Decoder:          decoder,
		Unit:             "pps",
		AttackType:       sig.AttackType,
		FirstSeen:        at,
		LastSeen:         at,
		SeenThisTick:     true,
		CurrentPPS:       int64(sig.CurrentPPS),
		CurrentBPS:       int64(sig.CurrentBPS),
		PeakPPS:          int64(sig.CurrentPPS),
		PeakBPS:          int64(sig.CurrentBPS),
		Confidence:       0.95,
	}
	if a.AttackType == "" {
		a.AttackType = decoderToAttackType(decoder)
	}
	if sig.NodeID != "" {
		a.NodeSources = []string{sig.NodeID}
	}
	t.attacks[key] = a
	if sig.NodeID != "" {
		t.markRing(a, sig.NodeID)
	}

	t.transitionToActive(a, at)
	return a.DBID, a.State == StateActive
}

// containsString reports membership in a small string slice.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
