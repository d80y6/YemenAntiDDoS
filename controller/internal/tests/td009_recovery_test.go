package tests

// TD-009 gates: restart recovery loads every active row (no 1000 cap) and ends
// duplicate canonical-key rows, keeping the newest started_at (ties: larger id).
// Setup failures are reported with a "device:" prefix so they are never read as
// behavioural red.

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sort"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/engine"
	"github.com/littlewolf9527/xsight/controller/internal/engine/dedup"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

type td009Fixture struct {
	s      *dao5AttackStore
	tk     *tracker.Tracker
	d      *dedup.Dedup
	events []tracker.AttackEvent
}

// td009New seeds rows through the MockStore chain (mockAttackRepo caps ListActive
// at 1000 like postgres, so the >1000 cell can be red on HEAD). The tracker-package
// dao13aRecoveryRepo is deliberately not used: it never caps.
func td009New(rows ...store.Attack) *td009Fixture {
	ms := NewMockStore()
	ms.attacks.appendAttacks(rows...)
	f := &td009Fixture{d: dedup.New()}
	f.s = &dao5AttackStore{MockStore: ms, r: &dao5Attacks{AttackRepo: ms.Attacks()}}
	f.tk = tracker.New(tracker.Config{HardConfirmSeconds: 1, ExpiryIntervalSeconds: 10, MaxActiveAttacks: 10000},
		f.s, nil, f.d, func(e tracker.AttackEvent) { f.events = append(f.events, e) })
	return f
}

func (f *td009Fixture) recover(t *testing.T) {
	t.Helper()
	if err := f.tk.RecoverFromDB(context.Background()); err != nil {
		t.Fatalf("device: RecoverFromDB: %v", err)
	}
}

func (f *td009Fixture) expired() map[int]int {
	out := map[int]int{}
	for _, e := range f.events {
		if e.Type == "expired" {
			out[e.DBID]++
		}
	}
	return out
}

func (f *td009Fixture) endedAt(t *testing.T, id int) *time.Time {
	t.Helper()
	row, err := f.s.MockStore.Attacks().Get(context.Background(), id)
	if err != nil {
		t.Fatalf("device: Get(%d): %v", id, err)
	}
	return row.EndedAt
}

func (f *td009Fixture) timerIDs() []int {
	var ids []int
	for id := range f.tk.ActiveTimers() {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func td009Row(id int, dst string, peak int64, started time.Time) store.Attack {
	return store.Attack{ID: id, DstIP: dst, Direction: "receives", DecoderFamily: "udp",
		AttackType: "udp_flood", Severity: "medium", PeakPPS: peak, StartedAt: started}
}

// td009Wide is a wide ip-decoder probe: it is suppressed only while the narrower
// udp key is registered in dedup (probing udp itself would never be suppressed).
func td009Wide(ip string) engine.ThresholdExceeded {
	return engine.ThresholdExceeded{DstIP: net.ParseIP(ip), Direction: "receives", Decoder: "ip"}
}

func TestTD009_T1_RecoverAllActive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var rows []store.Attack
		for i := 1; i <= 1001; i++ {
			rows = append(rows, td009Row(i, fmt.Sprintf("2001:db8:48::%x", i), int64(i), time.Now().Add(-time.Hour)))
		}
		f := td009New(rows...)
		f.recover(t)
		if n := f.tk.ActiveCount(); n != 1001 {
			t.Errorf("recovered ActiveCount=%d; want 1001", n)
		}
		for k := 0; k < 30; k++ {
			time.Sleep(time.Second)
			f.tk.Feed(nil)
		}
		got := f.expired()
		total, missing := 0, []int{}
		for _, n := range got {
			total += n
		}
		for i := 1; i <= 1001; i++ {
			if got[i] != 1 {
				missing = append(missing, i)
			}
		}
		if total != 1001 || len(got) != 1001 || len(missing) != 0 {
			t.Errorf("expired events=%d distinct=%d; want 1001/1001; ids without exactly one event (first 5)=%v", total, len(got), missing[:min(5, len(missing))])
		}
		active, err := f.s.MockStore.Attacks().CountActive(context.Background())
		if err != nil {
			t.Fatalf("device: CountActive: %v", err)
		}
		if active != 0 {
			t.Errorf("mock active rows after expiry=%d; want 0 (peak=1 row id 1 ended_at=%v)", active, f.endedAt(t, 1))
		}
	})
}

// T2: same canonical key as /32 text and bare address. The newer row has the
// higher peak (so HEAD's peak-desc overwrite keeps the older one) and the smaller
// id (so "keep the larger id" alone cannot pass).
func TestTD009_T2_CollisionKeepsNewest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const newID, oldID = 1, 2
		old := td009Row(oldID, "192.0.2.20/32", 100, time.Now().Add(-2*time.Hour))
		newer := td009Row(newID, "192.0.2.20", 200, time.Now().Add(-time.Hour))
		f := td009New(old, newer)
		probe := td009Wide("192.0.2.20")
		if f.d.ShouldSuppress(probe) {
			t.Fatal("device: wide probe suppressed before recovery")
		}
		f.recover(t)
		if n := f.tk.ActiveCount(); n != 1 {
			t.Errorf("ActiveCount=%d; want 1", n)
		}
		if ids := f.timerIDs(); !reflect.DeepEqual(ids, []int{newID}) {
			t.Errorf("ActiveTimers ids=%v; want [%d] (newest started_at kept)", ids, newID)
		}
		if f.endedAt(t, oldID) == nil {
			t.Errorf("older duplicate id %d still has ended_at NULL", oldID)
		}
		if e := f.endedAt(t, newID); e != nil {
			t.Errorf("kept row id %d ended_at=%v; want NULL", newID, e)
		}
		if got := f.expired(); !reflect.DeepEqual(got, map[int]int{oldID: 1}) {
			t.Errorf("expired events by DBID=%v; want {%d:1}", got, oldID)
		}
		if !f.d.ShouldSuppress(probe) {
			t.Error("kept key lost its dedup registration (wide ip probe not suppressed)")
		}
		if creates, _ := f.s.r.counts(); creates != 0 {
			t.Errorf("recovery created %d rows; want 0", creates)
		}
	})
}

// T3: equal started_at keeps the larger id. The smaller id carries the higher
// peak so "keep the highest peak" fails this cell.
func TestTD009_T3_CollisionTieKeepsLargerID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const smallID, bigID = 5, 6
		started := time.Now().Add(-time.Hour)
		f := td009New(td009Row(bigID, "2001:db8::30", 100, started), td009Row(smallID, "2001:db8::30/128", 300, started))
		probe := td009Wide("2001:db8::30")
		f.recover(t)
		if ids := f.timerIDs(); !reflect.DeepEqual(ids, []int{bigID}) {
			t.Errorf("ActiveTimers ids=%v; want [%d] (tie keeps larger id)", ids, bigID)
		}
		if f.endedAt(t, smallID) == nil {
			t.Errorf("smaller-id duplicate %d still has ended_at NULL", smallID)
		}
		if e := f.endedAt(t, bigID); e != nil {
			t.Errorf("kept row id %d ended_at=%v; want NULL", bigID, e)
		}
		if got := f.expired(); !reflect.DeepEqual(got, map[int]int{smallID: 1}) {
			t.Errorf("expired events by DBID=%v; want {%d:1}", got, smallID)
		}
		if !f.d.ShouldSuppress(probe) {
			t.Error("kept key lost its dedup registration (wide ip probe not suppressed)")
		}
	})
}

// T4: both Update attempts for the duplicate fail. Everything is observed before
// the ForceExpire probe, so the probe's true can only come from the pending branch.
func TestTD009_T4_DuplicateUpdateFailureGoesPending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const keepID, dupID = 7, 8
		f := td009New(td009Row(dupID, "198.51.100.40/32", 100, time.Now().Add(-2*time.Hour)),
			td009Row(keepID, "198.51.100.40", 200, time.Now().Add(-time.Hour)))
		probe := td009Wide("198.51.100.40")
		f.s.r.failUpdates(2, 0)
		recoveredAt := time.Now()
		f.recover(t)

		_, updates := f.s.r.counts()
		f.s.r.mu.Lock()
		unused := f.s.r.updateFailures
		f.s.r.mu.Unlock()
		if updates != 2 || unused != 0 || f.endedAt(t, dupID) != nil {
			t.Fatalf("before probe: updates=%d unused injected failures=%d dup ended_at=%v; want 2 failed updates, ended_at NULL", updates, unused, f.endedAt(t, dupID))
		}
		if got := f.expired(); !reflect.DeepEqual(got, map[int]int{dupID: 1}) || len(f.events) != 1 {
			t.Fatalf("before probe: events=%d expired by DBID=%v; want exactly {%d:1}", len(f.events), got, dupID)
		}
		if ids := f.timerIDs(); !reflect.DeepEqual(ids, []int{keepID}) {
			t.Fatalf("before probe: ActiveTimers ids=%v; want [%d]", ids, keepID)
		}
		if !f.d.ShouldSuppress(probe) {
			t.Fatal("before probe: kept key lost its dedup registration")
		}

		if !f.tk.ForceExpire(dupID) {
			t.Fatalf("ForceExpire(%d)=false; want true from the pending-end branch", dupID)
		}
		_, after := f.s.r.counts()
		if after != 2 || len(f.events) != 1 {
			t.Errorf("probe side effects: updates=%d events=%d; want 2/1", after, len(f.events))
		}
		if ids := f.timerIDs(); !reflect.DeepEqual(ids, []int{keepID}) {
			t.Errorf("after probe: ActiveTimers ids=%v; want [%d]", ids, keepID)
		}
		if !f.d.ShouldSuppress(probe) {
			t.Error("after probe: kept key lost its dedup registration")
		}

		// Pending retry (5 s spacing) persists the original ended_at without a second event.
		for k := 0; k < 6; k++ {
			time.Sleep(time.Second)
			f.tk.Feed(nil)
		}
		_, final := f.s.r.counts()
		ended := f.endedAt(t, dupID)
		if final != 3 || ended == nil || !ended.Equal(recoveredAt) || f.expired()[dupID] != 1 {
			t.Errorf("pending retry: updates=%d dup ended_at=%v expired(dup)=%d; want 3/%v/1", final, ended, f.expired()[dupID], recoveredAt)
		}
	})
}

func TestTD009_T5_NoCollisionNoSideEffects(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td009New(
			td009Row(1, "192.0.2.51/32", 10, time.Now().Add(-time.Hour)),
			td009Row(2, "192.0.2.52", 20, time.Now().Add(-2*time.Hour)),
			td009Row(3, "2001:db8::53/128", 30, time.Now().Add(-3*time.Hour)),
		)
		f.recover(t)
		creates, updates := f.s.r.counts()
		if len(f.events) != 0 || creates != 0 || updates != 0 {
			t.Errorf("recovery side effects: events=%d creates=%d updates=%d; want 0/0/0", len(f.events), creates, updates)
		}
		if n := f.tk.ActiveCount(); n != 3 {
			t.Errorf("ActiveCount=%d; want 3", n)
		}
	})
}

// C5 (mock only): rows injected out of id order come back in id order. The peak
// and started_at orders differ from id order, and the result is never re-sorted.
func TestTD009_C5_MockListAllActiveOrderID(t *testing.T) {
	ms := NewMockStore()
	now := time.Now()
	ms.attacks.appendAttacks(
		td009Row(3, "192.0.2.63", 10, now.Add(-2*time.Hour)),
		td009Row(1, "192.0.2.61", 20, now.Add(-time.Hour)),
		td009Row(2, "192.0.2.62", 30, now.Add(-3*time.Hour)),
	)
	rows, err := ms.Attacks().ListAllActive(context.Background())
	if err != nil {
		t.Fatalf("device: ListAllActive: %v", err)
	}
	ids := []int{}
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	if !reflect.DeepEqual(ids, []int{1, 2, 3}) {
		t.Errorf("ListAllActive raw ids=%v; want [1 2 3]", ids)
	}
}
