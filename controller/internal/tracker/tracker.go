// Package tracker implements the AttackTracker state machine.
package tracker

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
)

const trackerDBOperationTimeout = 5 * time.Second

const pendingEndRetryInterval = 5 * time.Second

// Attack states
const (
	StateConfirming = "confirming"
	StateActive     = "active"
	StateExpiring   = "expiring"
	StateExpired    = "expired"
)

// Config holds tracker parameters.
type Config struct {
	HardConfirmSeconds      int     // default 3
	DynamicConfirmSeconds   int     // default 5
	ExpiryIntervalSeconds   int     // default 300
	ExpiryFunction          string  // "static" | "dynamic", default "static"
	ExpiryScaleBaseSeconds  int     // attack duration for 1x scale (default 300)
	ExpiryMaxScale          float64 // max multiplier (default 4.0)
	MaxActiveAttacks        int     // default 10000, 0 = no limit
	ManualExpireHoldSeconds int     // seconds a manually expired key stays held; 0 = remove immediately
	// FastPathMultiplier promotes an attack straight to active on the first
	// tick when the measured value is at least this multiple of the threshold.
	// This is the zero-touch fast path for hit-and-run floods that would end
	// before the normal confirm window elapses. 0 disables the shortcut.
	FastPathMultiplier float64
}

// attackKey uniquely identifies an attack.
// Reference: brainstorm-controller.md "Attack Identity"
type attackKey struct {
	DstIP         string // IP string or prefix CIDR for carpet bombing
	Direction     string
	DecoderFamily string
}

// trackedAttack is the in-memory state of a single attack.
type trackedAttack struct {
	Key    attackKey
	State  string
	DBID   int    // attacks table ID (0 until INSERT)
	Prefix string // owning prefix CIDR

	// Confirmation
	ConsecutiveExceeded int
	ConfirmThreshold    int // seconds needed to confirm

	// Peak tracking
	PeakPPS    int64
	PeakBPS    int64
	CurrentPPS int64
	CurrentBPS int64

	// Threshold info
	PrefixID    int
	ThresholdID int
	ResponseID  *int
	Decoder     string
	Unit        string
	ThreshValue int64

	// Attack classification
	AttackType  string
	Severity    string
	Confidence  float32
	ReasonCodes []string
	NodeSources []string

	// Timing
	FirstSeen time.Time
	LastSeen  time.Time
	ExpiresAt time.Time // expiring: expiry deadline; expired (manual hold): hold deadline

	// Flags
	SeenThisTick  bool // reset each tick, set when threshold exceeded
	tickSustained int
}

// eventAttack supplies the lifecycle event field contract from tracker memory.
func (a *trackedAttack) eventAttack() *store.Attack {
	attack := &store.Attack{
		ID: a.DBID, DstIP: a.Key.DstIP, Direction: a.Key.Direction, DecoderFamily: a.Key.DecoderFamily,
		AttackType: a.AttackType, Severity: a.Severity, Confidence: a.Confidence,
		PeakPPS: a.PeakPPS, PeakBPS: a.PeakBPS, ReasonCodes: a.ReasonCodes, NodeSources: a.NodeSources,
		ResponseID: a.ResponseID, StartedAt: a.FirstSeen,
	}
	if a.PrefixID > 0 {
		value := a.PrefixID
		attack.PrefixID = &value
	}
	if a.ThresholdID > 0 {
		value := a.ThresholdID
		attack.ThresholdRuleID = &value
	}
	return attack
}

// ActionCallback is called when an attack state changes.
// Phase 5 wires this to the Action Engine.
type ActionCallback func(event AttackEvent)

// AttackEvent describes a state change in an attack's lifecycle.
type AttackEvent struct {
	Type   string // "confirmed" | "updated" | "type_upgrade" | "expired"
	Attack *store.Attack
	DBID   int
}

// pendingEndWrite retains an ended attack whose two immediate database writes failed.
// Its lastTry controls eligibility and retry ordering under the tracker lock.
type pendingEndWrite struct {
	attack  *store.Attack
	op      string
	lastTry time.Time
}

// Tracker manages the lifecycle of all tracked attacks.
type Tracker struct {
	mu         sync.RWMutex
	attacks    map[attackKey]*trackedAttack
	cfg        Config
	store      store.Store
	rings      *ring.RingStore
	dedup      *dedup.Dedup
	onAction   ActionCallback
	onRebreach func(attackDBID int) // called when attack transitions Expiring→Active

	// Periodic update tracking
	lastPeriodicUpdate time.Time
	pendingEnd         map[int]*pendingEndWrite
	pendingEndNextTry  time.Time

	// Set before Feed starts; metrics owns the counter to avoid an import cycle.
	StateWriteFailure func(string)

	// Metrics (read concurrently by API handlers)
	CreatedTotal    atomic.Int64
	SuppressedTotal atomic.Int64
	EvictedTotal    atomic.Int64
}

func New(cfg Config, s store.Store, rings *ring.RingStore, d *dedup.Dedup, onAction ActionCallback) *Tracker {
	return &Tracker{
		attacks:            make(map[attackKey]*trackedAttack),
		cfg:                cfg,
		rings:              rings,
		lastPeriodicUpdate: time.Now(),
		store:              s,
		dedup:              d,
		onAction:           onAction,
	}
}

// SetRebreachCallback sets a callback invoked when an attack transitions Expiring→Active.
// Used by the action engine to cancel pending delayed unblocks/withdrawals.
func (t *Tracker) SetRebreachCallback(fn func(attackDBID int)) {
	t.onRebreach = fn
}

// canonicalHostKey gives host-length prefixes the same identity as individual IPs.
// Broader prefixes and non-CIDR text retain their original identity.
func canonicalHostKey(s string) string {
	ip, network, err := net.ParseCIDR(s)
	if err == nil {
		ones, bits := network.Mask.Size()
		if ones == bits {
			return ip.String()
		}
	}
	return s
}

// Feed processes threshold exceeded events from the detection engine.
// Called after each detection tick (1/second).
func (t *Tracker) Feed(exceeded []engine.ThresholdExceeded) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()

	// Reset per-tick flags
	for _, a := range t.attacks {
		a.SeenThisTick = false
		a.tickSustained = 0
	}

	// Process exceeded events
	for _, evt := range exceeded {
		dstIP := ""
		if evt.DstIP != nil {
			dstIP = evt.DstIP.String()
		} else if evt.Domain == "subnet" {
			dstIP = canonicalHostKey(evt.Prefix)
		}

		key := attackKey{
			DstIP:         dstIP,
			Direction:     evt.Direction,
			DecoderFamily: evt.Decoder,
		}

		a, exists := t.attacks[key]
		if !exists {
			// New potential attack — use confirm seconds based on detection source
			confirmSec := t.cfg.HardConfirmSeconds
			if evt.Source == "dynamic" {
				confirmSec = t.cfg.DynamicConfirmSeconds
			}
			a = &trackedAttack{
				Key:              key,
				State:            StateConfirming,
				Prefix:           evt.Prefix,
				PrefixID:         evt.PrefixID,
				ConfirmThreshold: confirmSec,
				Decoder:          evt.Decoder,
				Unit:             evt.Unit,
				ThresholdID:      evt.ThresholdID,
				ResponseID:       evt.ResponseID,
				ThreshValue:      evt.Value,
				FirstSeen:        now,
				NodeSources:      []string{evt.NodeID},
			}
			// Set initial attack type from decoder
			a.AttackType = decoderToAttackType(evt.Decoder)
			t.attacks[key] = a
			t.markRing(a, evt.NodeID)
		}

		a.SeenThisTick = true
		sus := evt.Sustained
		if sus == 0 {
			sus = math.MaxInt
		}
		if sus > a.tickSustained {
			a.tickSustained = sus
		}
		a.LastSeen = now
		// Zero-touch fast path: an overwhelming first-second rate is its own
		// confirmation. Without this, a 2-3 second hit-and-run flood ends before
		// the sustain window elapses and nothing is ever mitigated.
		if t.cfg.FastPathMultiplier > 0 && evt.Value > 0 &&
			float64(evt.Actual) >= t.cfg.FastPathMultiplier*float64(evt.Value) {
			if a.ConsecutiveExceeded < a.ConfirmThreshold {
				a.ConsecutiveExceeded = a.ConfirmThreshold
			}
			if a.tickSustained < a.ConfirmThreshold {
				a.tickSustained = a.ConfirmThreshold
			}
		}
		// NOTE: ownership fields (PrefixID, ThresholdID, ResponseID) are intentionally NOT refreshed
		// on subsequent threshold hits. This is first-writer-wins: the earliest matching rule determines
		// the response binding for the entire attack lifecycle. Changing response mid-attack would risk
		// xDrop rule conflicts and inconsistent action execution.
		a.CurrentPPS = max(a.CurrentPPS, evt.Actual)
		if evt.Unit == "pps" && evt.Actual > a.PeakPPS {
			a.PeakPPS = evt.Actual
		}
		if evt.Unit == "bps" && evt.Actual > a.PeakBPS {
			a.PeakBPS = evt.Actual
		}

		// Add node source if new + protect its ring from eviction
		if evt.NodeID != "" {
			found := false
			for _, ns := range a.NodeSources {
				if ns == evt.NodeID {
					found = true
					break
				}
			}
			if !found {
				a.NodeSources = append(a.NodeSources, evt.NodeID)
				// Protect the new node's IP ring during confirmation and active detection
				if a.State == StateActive || a.State == StateConfirming {
					if ip := net.ParseIP(a.Key.DstIP); ip != nil && t.rings != nil {
						if a.Key.Direction == "sends" {
							t.rings.MarkSrcActive(evt.NodeID, a.Prefix, ip)
						} else {
							t.rings.MarkActive(evt.NodeID, a.Prefix, ip)
						}
					}
				}
			}
		}
	}

	// Tick state machine for all tracked attacks
	t.tick(now)
}

// tick advances all attack state machines.
func (t *Tracker) tick(now time.Time) {
	var toDelete []attackKey
	var discarded []*trackedAttack

	for key, a := range t.attacks {
		switch a.State {
		case StateConfirming:
			if a.SeenThisTick {
				a.ConsecutiveExceeded++
				// Confirmation requires both consecutive detection ticks and breaching data points.
				if a.ConsecutiveExceeded >= a.ConfirmThreshold && a.tickSustained >= a.ConfirmThreshold {
					t.transitionToActive(a, now)
				}
			} else {
				// Reset after a missed tick; release unshared ring protection after all deletions.
				toDelete = append(toDelete, key)
				discarded = append(discarded, a)
			}

		case StateActive:
			if a.SeenThisTick {
				// Still active — peaks already updated in Feed.
				// Periodic update: emit attack_update every 5 minutes for ongoing attacks.
			} else {
				// Dropped below threshold → start expiry timer
				a.State = StateExpiring
				expirySec := t.cfg.ExpiryIntervalSeconds
				if t.cfg.ExpiryFunction == "dynamic" {
					duration := now.Sub(a.FirstSeen).Seconds()
					scale := duration / float64(t.cfg.ExpiryScaleBaseSeconds)
					if scale < 1.0 {
						scale = 1.0
					}
					if scale > t.cfg.ExpiryMaxScale {
						scale = t.cfg.ExpiryMaxScale
					}
					expirySec = int(float64(expirySec) * scale)
				}
				a.ExpiresAt = now.Add(time.Duration(expirySec) * time.Second)
				log.Printf("tracker: attack %s/%s expiring (expires in %ds)",
					a.Key.DstIP, a.Key.DecoderFamily, expirySec)
			}

		case StateExpiring:
			if a.SeenThisTick {
				// Re-exceeded — back to active
				a.State = StateActive
				a.ExpiresAt = time.Time{}
				log.Printf("tracker: attack %s/%s back to active (re-exceeded)",
					a.Key.DstIP, a.Key.DecoderFamily)
				// Cancel any pending delayed unblocks/withdrawals
				if t.onRebreach != nil && a.DBID > 0 {
					t.onRebreach(a.DBID)
				}
			} else if now.After(a.ExpiresAt) {
				// Timer expired → archive
				t.transitionToExpired(a, now)
				toDelete = append(toDelete, key)
			}

		case StateExpired:
			// Manual expiry holds retain dedup registration until the first unseen
			// tick or the tick after the hold deadline. Ring protection is already cleared.
			if !a.SeenThisTick || now.After(a.ExpiresAt) {
				t.dedup.ClearActive(a.Key.DstIP, a.Key.Direction, a.Key.DecoderFamily)
				toDelete = append(toDelete, key)
			}
		}
	}

	// Remove expired/discarded attacks from memory
	for _, key := range toDelete {
		delete(t.attacks, key)
	}
	t.releaseDiscarded(discarded)

	// Periodic updates: every 5 minutes, emit attack_update for all active attacks
	if now.Sub(t.lastPeriodicUpdate) >= 5*time.Minute {
		t.lastPeriodicUpdate = now
		for _, a := range t.attacks {
			if a.State == StateActive && a.DBID > 0 {
				// Update DB with latest peaks
				ctx, cancel := context.WithTimeout(context.Background(), trackerDBOperationTimeout)
				attack := a.eventAttack()
				if err := t.store.Attacks().Update(ctx, attack); err != nil {
					log.Printf("tracker: periodic update attack %d: %v", a.DBID, err)
				}
				cancel()

				// Notify action engine with "updated" event
				if t.onAction != nil {
					t.notifyAction(AttackEvent{Type: "updated", Attack: attack, DBID: a.DBID})
				}
			}
		}
	}
	t.retryPendingEnd(now)
}

func (t *Tracker) transitionToActive(a *trackedAttack, now time.Time) {
	a.Severity = classifySeverity(a.PeakPPS, a.PeakBPS)
	a.Confidence = 0.9
	a.ReasonCodes = []string{a.Decoder + "_exceeded"}

	var evict *trackedAttack
	// Check active cap before creating
	if t.cfg.MaxActiveAttacks > 0 {
		activeCount := t.countActive()
		if activeCount >= t.cfg.MaxActiveAttacks {
			// Find the lowest priority active or expiring attack
			lowest := t.findLowestActive()
			if lowest != nil && evictionLess(lowest, a) {
				// Evict lowest, make room for new higher-priority attack
				evict = lowest
			} else {
				// New attack is lower priority — suppress
				t.SuppressedTotal.Add(1)
				log.Printf("tracker: attack suppressed: %s/%s pps=%d (cap %d reached, min active pps=%d)",
					a.Key.DstIP, a.Key.DecoderFamily, a.PeakPPS,
					t.cfg.MaxActiveAttacks, t.lowestActivePPS())
				// Stay confirming: retry, count, and log suppression on each tick where
				// both confirmation gates hold. A consecutive-point run below N pauses
				// retries; the first tick without a breach discards the entry.
				a.State = StateConfirming
				return
			}
		}
	}

	// INSERT into DB
	ctx, cancel := context.WithTimeout(context.Background(), trackerDBOperationTimeout)
	defer cancel()

	attack := a.eventAttack()

	// Snapshot template name + rule summary for historical display
	if a.ThresholdID > 0 {
		if rule, err := t.store.Thresholds().Get(ctx, a.ThresholdID); err == nil {
			summary := rule.Decoder + " " + rule.Comparison + " " + fmt.Sprintf("%d", rule.Value) + " " + rule.Unit
			attack.RuleSummary = &summary
			if rule.TemplateID != nil {
				if tmpl, err := t.store.ThresholdTemplates().Get(ctx, *rule.TemplateID); err == nil {
					attack.TemplateName = &tmpl.Name
				}
			}
		}
	}

	createCtx, createCancel := context.WithTimeout(context.Background(), trackerDBOperationTimeout)
	defer createCancel()
	id, err := t.store.Attacks().Create(createCtx, attack)
	if err != nil {
		log.Printf("ERROR tracker: DB insert attack: %v", err)
		if t.StateWriteFailure != nil {
			t.StateWriteFailure("attack_create")
		}
		return
	} else {
		a.DBID = id
		attack.ID = id
	}

	if lowest := evict; lowest != nil {
		t.evictAttack(lowest, now)
		log.Printf("tracker: attack evicted: %s/%s severity=%s pps=%d (replaced by %s severity=%s pps=%d)",
			lowest.Key.DstIP, lowest.Key.DecoderFamily, lowest.Severity, lowest.PeakPPS,
			a.Key.DstIP, a.Severity, a.PeakPPS)
	}

	a.State = StateActive
	t.CreatedTotal.Add(1)

	log.Printf("tracker: ATTACK CONFIRMED %s decoder=%s type=%s pps=%d prefix=%s",
		a.Key.DstIP, a.Key.DecoderFamily, a.AttackType, a.PeakPPS, a.Prefix)

	// Register with dedup + ring eviction protection (all nodes)
	t.dedup.MarkActive(a.Key.DstIP, a.Key.Direction, a.Key.DecoderFamily)
	if ip := net.ParseIP(a.Key.DstIP); ip != nil && t.rings != nil {
		for _, nodeID := range a.NodeSources {
			if a.Key.Direction == "sends" {
				t.rings.MarkSrcActive(nodeID, a.Prefix, ip)
			} else {
				t.rings.MarkActive(nodeID, a.Prefix, ip)
			}
		}
	}

	// Notify action engine
	if t.onAction != nil {
		t.notifyAction(AttackEvent{Type: "confirmed", Attack: attack, DBID: id})
	}
}

func (t *Tracker) transitionToExpired(a *trackedAttack, now time.Time) {
	t.endAttack(a, now, true)
}

func (t *Tracker) endAttack(a *trackedAttack, now time.Time, clearDedup bool) {
	a.State = StateExpired

	log.Printf("tracker: ATTACK EXPIRED %s decoder=%s duration=%v peak_pps=%d",
		a.Key.DstIP, a.Key.DecoderFamily, now.Sub(a.FirstSeen).Round(time.Second), a.PeakPPS)

	// Clear from dedup + ring eviction protection (all nodes)
	if clearDedup {
		t.dedup.ClearActive(a.Key.DstIP, a.Key.Direction, a.Key.DecoderFamily)
	}
	if ip := net.ParseIP(a.Key.DstIP); ip != nil && t.rings != nil {
		for _, nodeID := range a.NodeSources {
			if a.Key.Direction == "sends" {
				t.rings.ClearSrcActive(nodeID, a.Prefix, ip)
			} else {
				t.rings.ClearActive(nodeID, a.Prefix, ip)
			}
		}
	}

	// UPDATE DB with ended_at
	if a.DBID > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), trackerDBOperationTimeout)
		defer cancel()

		attack := &store.Attack{
			ID:          a.DBID,
			AttackType:  a.AttackType,
			Severity:    a.Severity,
			Confidence:  a.Confidence,
			PeakPPS:     a.PeakPPS,
			PeakBPS:     a.PeakBPS,
			ReasonCodes: a.ReasonCodes,
			NodeSources: a.NodeSources,
			ResponseID:  a.ResponseID,
			EndedAt:     &now,
		}
		if err := t.store.Attacks().Update(ctx, attack); err != nil {
			retryCtx, retryCancel := context.WithTimeout(context.Background(), trackerDBOperationTimeout)
			err = t.store.Attacks().Update(retryCtx, attack)
			retryCancel()
			if err != nil {
				log.Printf("ERROR tracker: DB update expired attack %d: %v", a.DBID, err)
				if t.StateWriteFailure != nil {
					t.StateWriteFailure("attack_update_expired")
				}
				t.queuePendingEnd(attack, "attack_update_expired")
			}
		}

		// Notify action engine — reload full attack from DB so all fields
		// (DstIP, PrefixID, ThresholdRuleID, ResponseID etc.) are available.
		if t.onAction != nil {
			fullAttack, err := t.store.Attacks().Get(ctx, a.DBID)
			if err != nil {
				log.Printf("tracker: DB reload expired attack %d: %v", a.DBID, err)
				fullAttack = a.eventAttack()
				fullAttack.EndedAt = &now
			} else if fullAttack.EndedAt == nil {
				fullAttack.EndedAt = &now
			}
			t.notifyAction(AttackEvent{Type: "expired", Attack: fullAttack, DBID: a.DBID})
		}
	}
}

// ForceExpire manually expires an attack using the configured in-memory hold.
// It also returns true for an ended attack still awaiting database persistence.
func (t *Tracker) ForceExpire(dbID int) bool {
	return t.ForceExpireHold(dbID, time.Duration(t.cfg.ManualExpireHoldSeconds)*time.Second)
}

// ForceExpireHold ends an attack and holds its key until traffic drops or hold elapses.
// A nonpositive hold removes it immediately. Pending writes never emit a second end event.
func (t *Tracker) ForceExpireHold(dbID int, hold time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	for key, a := range t.attacks {
		if a.DBID == dbID {
			now := time.Now()
			log.Printf("tracker: force-expire attack %s/%s (id=%d) by user", key.DstIP, key.DecoderFamily, dbID)
			t.endAttack(a, now, hold <= 0)
			if hold > 0 {
				a.DBID = 0
				a.ExpiresAt = now.Add(hold)
				log.Printf("tracker: holding %s/%s for up to %v after manual expire", key.DstIP, key.DecoderFamily, hold)
			} else {
				delete(t.attacks, key)
			}
			return true
		}
	}
	if _, ok := t.pendingEnd[dbID]; ok {
		log.Printf("tracker: attack %d already ended; awaiting database persistence", dbID)
		return true
	}
	return false
}

// queuePendingEnd snapshots the failed payload under t.mu. Enqueueing does not
// postpone the table-wide retry clock, so new failures cannot starve older ones.
func (t *Tracker) queuePendingEnd(attack *store.Attack, op string) {
	copy := *attack
	copy.ReasonCodes = slices.Clone(attack.ReasonCodes)
	copy.NodeSources = slices.Clone(attack.NodeSources)
	if attack.ResponseID != nil {
		v := *attack.ResponseID
		copy.ResponseID = &v
	}
	if attack.PrefixID != nil {
		v := *attack.PrefixID
		copy.PrefixID = &v
	}
	if attack.ThresholdRuleID != nil {
		v := *attack.ThresholdRuleID
		copy.ThresholdRuleID = &v
	}
	if attack.EndedAt != nil {
		v := *attack.EndedAt
		copy.EndedAt = &v
	}
	if attack.TemplateName != nil {
		v := *attack.TemplateName
		copy.TemplateName = &v
	}
	if attack.RuleSummary != nil {
		v := *attack.RuleSummary
		copy.RuleSummary = &v
	}
	if t.pendingEnd == nil {
		t.pendingEnd = make(map[int]*pendingEndWrite)
	}
	t.pendingEnd[attack.ID] = &pendingEndWrite{attack: &copy, op: op, lastTry: time.Now()}
}

// retryPendingEnd runs under t.mu and retries at most one eligible write per tick.
// Eligibility uses the tick's start, excluding entries queued in the same slow tick.
// The O(K) scan selects the oldest attempt; retries are spaced from completion.
func (t *Tracker) retryPendingEnd(tickStart time.Time) {
	if len(t.pendingEnd) == 0 || tickStart.Before(t.pendingEndNextTry) {
		return
	}
	var pick *pendingEndWrite
	pickID := 0
	for id, p := range t.pendingEnd {
		if tickStart.Before(p.lastTry.Add(pendingEndRetryInterval)) {
			continue
		}
		if pick == nil || p.lastTry.Before(pick.lastTry) || (p.lastTry.Equal(pick.lastTry) && id < pickID) {
			pick, pickID = p, id
		}
	}
	if pick == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), trackerDBOperationTimeout)
	err := t.store.Attacks().Update(ctx, pick.attack)
	cancel()
	done := time.Now()
	t.pendingEndNextTry = done.Add(pendingEndRetryInterval)
	if err != nil {
		pick.lastTry = done
	} else {
		delete(t.pendingEnd, pickID)
		log.Printf("tracker: %s ended_at for attack %d persisted on retry", pick.op, pickID)
	}
}

// NotifyExpired sends an on_expired event to the action engine for a DB-only expire.
// Used by manual expire API when the attack is not in tracker memory (degraded recovery / stale row).
func (t *Tracker) NotifyExpired(attack *store.Attack) {
	if t.onAction != nil {
		t.notifyAction(AttackEvent{Type: "expired", Attack: attack, DBID: attack.ID})
	}
}

// notifyAction hands off a snapshot without sharing mutable tracker fields.
// It runs at the original callback site, preserving lock and enqueue ordering.
func (t *Tracker) notifyAction(event AttackEvent) {
	attack := *event.Attack
	attack.NodeSources = slices.Clone(attack.NodeSources)
	attack.ReasonCodes = slices.Clone(attack.ReasonCodes)
	if attack.ResponseID != nil {
		responseID := *attack.ResponseID
		attack.ResponseID = &responseID
	}
	event.Attack = &attack
	t.onAction(event)
}

// ActiveTimers returns expiry timer info for all tracked attacks, keyed by DB ID.
// Used by the API to show countdown timers on active attacks.
type AttackTimer struct {
	Prefix         string  `json:"-"`
	ThresholdValue *int64  `json:"threshold_value,omitempty"`
	ThresholdUnit  string  `json:"threshold_unit,omitempty"`
	State          string  `json:"state"`      // "active" | "expiring"
	ExpiresIn      float64 `json:"expires_in"` // seconds until expiry (0 if active/not expiring)
}

func (t *Tracker) ActiveTimers() map[int]AttackTimer {
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := time.Now()
	result := make(map[int]AttackTimer, len(t.attacks))
	for _, a := range t.attacks {
		if a.DBID <= 0 {
			continue
		}
		timer := AttackTimer{State: a.State, Prefix: a.Prefix}
		if a.Unit != "" {
			value := a.ThreshValue
			timer.ThresholdValue = &value
			timer.ThresholdUnit = a.Unit
		}
		if a.State == StateExpiring && a.ExpiresAt.After(now) {
			timer.ExpiresIn = a.ExpiresAt.Sub(now).Seconds()
		}
		result[a.DBID] = timer
	}
	return result
}

// UpgradeType updates the attack type based on classifier results.
// Reference: brainstorm-controller.md "Type upgrade rules"
func (t *Tracker) UpgradeType(dstIP net.IP, newType string, confidence float32, reasons []string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	ipStr := dstIP.String()
	for _, a := range t.attacks {
		if a.Key.DstIP == ipStr && a.State == StateActive && a.Key.Direction != "sends" {
			// Only upgrade UDP attacks with classifier results
			// (classifier only analyzes UDP src_port distribution)
			if a.Key.DecoderFamily != "udp" {
				continue
			}
			if a.AttackType == newType {
				continue
			}
			oldType := a.AttackType
			a.AttackType = newType
			a.Confidence = confidence
			a.ReasonCodes = append(a.ReasonCodes, reasons...)

			log.Printf("tracker: type upgrade %s: %s → %s (confidence=%.2f)",
				ipStr, oldType, newType, confidence)

			// Update DB
			if a.DBID > 0 {
				ctx, cancel := context.WithTimeout(context.Background(), trackerDBOperationTimeout)
				defer cancel()
				attack := a.eventAttack()
				if err := t.store.Attacks().Update(ctx, attack); err != nil {
					log.Printf("tracker: DB update type upgrade %d: %v", a.DBID, err)
				}

				// Notify action engine — immediate re-evaluation
				if t.onAction != nil {
					t.notifyAction(AttackEvent{Type: "type_upgrade", Attack: attack, DBID: a.DBID})
				}
			}
		}
	}
}

// RecoverFromDB rebuilds in-memory state from active attacks in DB.
// Called on Controller startup for crash recovery.
func (t *Tracker) RecoverFromDB(ctx context.Context) error {
	attacks, err := t.store.Attacks().ListAllActive(ctx)
	if err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	kept := make(map[attackKey]*trackedAttack)
	var duplicates []*trackedAttack
	for _, a := range attacks {
		key := attackKey{
			DstIP:         canonicalHostKey(a.DstIP),
			Direction:     a.Direction,
			DecoderFamily: a.DecoderFamily,
		}
		ta := &trackedAttack{
			Key:         key,
			State:       StateActive,
			DBID:        a.ID,
			Prefix:      "", // will be resolved on next detection tick
			AttackType:  a.AttackType,
			Severity:    a.Severity,
			PeakPPS:     a.PeakPPS,
			PeakBPS:     a.PeakBPS,
			ReasonCodes: a.ReasonCodes,
			NodeSources: a.NodeSources,
			FirstSeen:   a.StartedAt,
			LastSeen:    time.Now(),
		}
		ta.Confidence = a.Confidence
		if a.PrefixID != nil {
			ta.PrefixID = *a.PrefixID
		}
		if a.ThresholdRuleID != nil {
			ta.ThresholdID = *a.ThresholdRuleID
		}
		if a.ResponseID != nil {
			ta.ResponseID = a.ResponseID
		}
		if current, ok := kept[key]; ok {
			if ta.FirstSeen.After(current.FirstSeen) || (ta.FirstSeen.Equal(current.FirstSeen) && ta.DBID > current.DBID) {
				duplicates = append(duplicates, current)
				kept[key] = ta
			} else {
				duplicates = append(duplicates, ta)
			}
		} else {
			kept[key] = ta
		}
	}

	for key, ta := range kept {
		t.attacks[key] = ta
		t.dedup.MarkActive(key.DstIP, key.Direction, key.DecoderFamily)
	}

	now := time.Now()
	for _, dup := range duplicates {
		t.endAttack(dup, now, false)
	}

	if len(kept) > 0 {
		log.Printf("tracker: recovered %d active attacks from DB", len(kept))
	}
	if len(duplicates) > 0 {
		log.Printf("tracker: recovery ended %d duplicate-key active attacks", len(duplicates))
	}
	return nil
}

// ActiveDstIPs returns the dst IP strings of all active/expiring attacks.
// Used by the classifier to attempt type upgrades on active attacks.
func (t *Tracker) ActiveDstIPs() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	seen := make(map[string]bool)
	var ips []string
	for _, a := range t.attacks {
		if (a.State == StateActive || a.State == StateExpiring) && !seen[a.Key.DstIP] {
			seen[a.Key.DstIP] = true
			ips = append(ips, a.Key.DstIP)
		}
	}
	return ips
}

// ActiveCount returns the number of currently tracked attacks.
func (t *Tracker) ActiveCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	count := 0
	for _, a := range t.attacks {
		if a.State == StateActive || a.State == StateExpiring {
			count++
		}
	}
	return count
}

// decoderToAttackType maps a decoder_family value to the human-readable
// attack_type string stored on the attack record and surfaced in the UI /
// API. The mapping follows two conventions:
//
//   - Protocol-specific decoders → "<short>_flood" (e.g. tcp_syn → syn_flood,
//     tcp_ack → ack_flood, gre → gre_flood). The TCP-flag family drops the
//     "tcp_" prefix so the name reads naturally ("ack_flood" not "tcp_ack_flood").
//   - L3 aggregates (ip / ip_other) → "volumetric_*" because there is no
//     concrete protocol to name; the attack is just "lots of packets".
//   - Anomaly decoders (bad_fragment / invalid) → "<decoder>_flood" — the
//     name carries the malformed-packet semantics already.
//
// Keep this list in sync with shared/decoder.Names. New decoders that aren't
// added here render as "unknown" and break attack_type preconditions silently.
func decoderToAttackType(decoder string) string {
	switch decoder {
	// L4 standard
	case "tcp":
		return "tcp_flood"
	case "tcp_syn":
		return "syn_flood"
	case "udp":
		return "udp_flood"
	case "icmp":
		return "icmp_flood"
	case "fragment":
		return "fragment_flood"
	// TCP flag family (v1.3)
	case "tcp_ack":
		return "ack_flood"
	case "tcp_rst":
		return "rst_flood"
	case "tcp_fin":
		return "fin_flood"
	// Other IP protocols (v1.3)
	case "gre":
		return "gre_flood"
	case "esp":
		return "esp_flood"
	case "igmp":
		return "igmp_flood"
	// L3 aggregates
	case "ip":
		return "volumetric_generic"
	case "ip_other":
		return "volumetric_other"
	// Anomaly family (v1.3)
	case "bad_fragment":
		return "bad_fragment_flood"
	case "invalid":
		return "invalid_packet_flood"
	default:
		return "unknown"
	}
}

const (
	severityCriticalPPS = 1_000_000
	severityCriticalBPS = 10_000_000_000
	severityHighPPS     = 100_000
	severityHighBPS     = 1_000_000_000
	severityMediumPPS   = 10_000
	severityMediumBPS   = 100_000_000
)

func classifySeverity(peakPPS, peakBPS int64) string {
	if peakPPS > severityCriticalPPS || peakBPS > severityCriticalBPS {
		return "critical"
	}
	if peakPPS > severityHighPPS || peakBPS > severityHighBPS {
		return "high"
	}
	if peakPPS > severityMediumPPS || peakBPS > severityMediumBPS {
		return "medium"
	}
	return "low"
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// --- Active cap helpers (must be called with t.mu held) ---

// severityScore maps severity string to a numeric rank for priority comparison.
// Higher score = higher priority = less likely to be evicted.
func severityScore(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// attackPriorityLess returns true if a is lower priority than b.
// Compares severity first, then PeakPPS as tiebreaker.
func attackPriorityLess(a, b *trackedAttack) bool {
	sa, sb := severityScore(a.Severity), severityScore(b.Severity)
	if sa != sb {
		return sa < sb
	}
	return a.PeakPPS < b.PeakPPS
}

// evictionLess orders cap candidates by severity, then pending expiry, then PeakPPS.
// An expiring attack seen this tick is treated as active even before tick restores it.
func evictionLess(a, b *trackedAttack) bool {
	sa, sb := severityScore(a.Severity), severityScore(b.Severity)
	if sa != sb {
		return sa < sb
	}
	ae, be := a.State == StateExpiring && !a.SeenThisTick, b.State == StateExpiring && !b.SeenThisTick
	if ae != be {
		return ae
	}
	return a.PeakPPS < b.PeakPPS
}

// countActive counts active/expiring attacks, the same set as findLowestActive.
func (t *Tracker) countActive() int {
	count := 0
	for _, a := range t.attacks {
		if a.State == StateActive || a.State == StateExpiring {
			count++
		}
	}
	return count
}

// findLowestActive selects the lowest eviction priority among active/expiring attacks.
func (t *Tracker) findLowestActive() *trackedAttack {
	var lowest *trackedAttack
	for _, a := range t.attacks {
		if a.State == StateActive || a.State == StateExpiring {
			if lowest == nil || evictionLess(a, lowest) {
				lowest = a
			}
		}
	}
	return lowest
}

// lowestActivePPS returns the minimum peak_pps among active attacks.
func (t *Tracker) lowestActivePPS() int64 {
	l := t.findLowestActive()
	if l == nil {
		return 0
	}
	return l.PeakPPS
}

// evictAttack removes an active attack due to cap pressure.
// Writes ended_at to DB with evicted reason, notifies action engine.
func (t *Tracker) evictAttack(a *trackedAttack, now time.Time) {
	t.EvictedTotal.Add(1)

	// Clear from dedup + ring (all nodes)
	t.dedup.ClearActive(a.Key.DstIP, a.Key.Direction, a.Key.DecoderFamily)
	if ip := net.ParseIP(a.Key.DstIP); ip != nil && t.rings != nil {
		for _, nodeID := range a.NodeSources {
			if a.Key.Direction == "sends" {
				t.rings.ClearSrcActive(nodeID, a.Prefix, ip)
			} else {
				t.rings.ClearActive(nodeID, a.Prefix, ip)
			}
		}
	}

	// Update DB — mark as ended with evicted reason
	if a.DBID > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), trackerDBOperationTimeout)
		defer cancel()
		attack := a.eventAttack()
		attack.EndedAt = &now
		attack.ReasonCodes = append(a.ReasonCodes, "evicted_by_cap")
		if err := t.store.Attacks().Update(ctx, attack); err != nil {
			retryCtx, retryCancel := context.WithTimeout(context.Background(), trackerDBOperationTimeout)
			err = t.store.Attacks().Update(retryCtx, attack)
			retryCancel()
			if err != nil {
				log.Printf("ERROR tracker: DB update evicted attack %d: %v", a.DBID, err)
				if t.StateWriteFailure != nil {
					t.StateWriteFailure("attack_update_evicted")
				}
				t.queuePendingEnd(attack, "attack_update_evicted")
			}
		}

		// Notify action engine — evicted, not naturally expired
		if t.onAction != nil {
			t.notifyAction(AttackEvent{Type: "evicted", Attack: attack, DBID: a.DBID})
		}
	}

	// Remove from tracker
	delete(t.attacks, a.Key)
}

// markRing protects a confirming attack's source using the existing ring protection bit.
func (t *Tracker) markRing(a *trackedAttack, nodeID string) {
	if ip := net.ParseIP(a.Key.DstIP); ip != nil && t.rings != nil && nodeID != "" {
		if a.Key.Direction == "sends" {
			t.rings.MarkSrcActive(nodeID, a.Prefix, ip)
		} else {
			t.rings.MarkActive(nodeID, a.Prefix, ip)
		}
	}
}

// releaseDiscarded runs after the tick's deletions. Shared slots retain protection
// while another confirming, active, or expiring attack still occupies them.
func (t *Tracker) releaseDiscarded(discarded []*trackedAttack) {
	if len(discarded) == 0 || t.rings == nil {
		return
	}
	type ringSlot struct{ node, prefix, ip, direction string }
	ringDir := func(direction string) string {
		if direction == "sends" {
			return "sends"
		}
		return "receives"
	}
	held := make(map[ringSlot]bool)
	for _, a := range t.attacks {
		if a.State == StateExpired {
			continue
		}
		for _, n := range a.NodeSources {
			held[ringSlot{n, a.Prefix, a.Key.DstIP, ringDir(a.Key.Direction)}] = true
		}
	}
	for _, a := range discarded {
		ip := net.ParseIP(a.Key.DstIP)
		if ip == nil {
			continue
		}
		for _, n := range a.NodeSources {
			if held[ringSlot{n, a.Prefix, a.Key.DstIP, ringDir(a.Key.Direction)}] {
				continue
			}
			if a.Key.Direction == "sends" {
				t.rings.ClearSrcActive(n, a.Prefix, ip)
			} else {
				t.rings.ClearActive(n, a.Prefix, ip)
			}
		}
	}
}
