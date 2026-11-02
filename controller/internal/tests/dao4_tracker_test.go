package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
)

type dao4AttackStore struct {
	*MockStore
	getFails bool
}
type dao4AttackRepo struct {
	store.AttackRepo
	getFails bool
}

func (s dao4AttackStore) Attacks() store.AttackRepo {
	return dao4AttackRepo{s.MockStore.Attacks(), s.getFails}
}
func (r dao4AttackRepo) Get(ctx context.Context, id int) (*store.Attack, error) {
	if r.getFails {
		return nil, errors.New("dao4 get fault")
	}
	return r.AttackRepo.Get(ctx, id)
}
func dao4Threshold(nulls bool) []engine.ThresholdExceeded {
	x := engine.ThresholdExceeded{DstIP: net.ParseIP("192.0.2.10"), Prefix: "192.0.2.0/24", PrefixID: 7, ThresholdID: 8, ResponseID: intPtr(1), Direction: "receives", Decoder: "udp", Unit: "pps", Actual: 25001, NodeID: "n1"}
	if nulls {
		x.PrefixID = 0
		x.ThresholdID = 0
		x.ResponseID = nil
	}
	y := x
	y.Unit = "bps"
	y.Actual = 800000
	return []engine.ThresholdExceeded{x, y}
}
func dao4Tracker(s store.Store, cb tracker.ActionCallback) *tracker.Tracker {
	return tracker.New(tracker.Config{HardConfirmSeconds: 1, ExpiryIntervalSeconds: 300, MaxActiveAttacks: 1}, s, nil, dedup.New(), cb)
}
func dao4Tick(tk *tracker.Tracker, rows []engine.ThresholdExceeded) {
	// Virtual timer, advanced by synctest only when all goroutines block.
	// This models a periodic detector tick without wall-clock sleep.
	timer := time.NewTimer(6 * time.Minute)
	<-timer.C
	tk.Feed(rows)
}
func dao4Evict(tk *tracker.Tracker) {
	next := dao4Threshold(false)
	for i := range next {
		next[i].DstIP = net.ParseIP("192.0.2.11")
		next[i].Actual = 2000000
	}
	tk.Feed(append(dao4Threshold(false), next...))
}
func dao4AttackFields(a store.Attack) store.Attack {
	return store.Attack{ID: a.ID, DstIP: a.DstIP, Direction: a.Direction, DecoderFamily: a.DecoderFamily, PrefixID: a.PrefixID, ThresholdRuleID: a.ThresholdRuleID, AttackType: a.AttackType, Severity: a.Severity, Confidence: a.Confidence, PeakPPS: a.PeakPPS, PeakBPS: a.PeakBPS, ReasonCodes: a.ReasonCodes, NodeSources: a.NodeSources, ResponseID: a.ResponseID, StartedAt: a.StartedAt, EndedAt: a.EndedAt}
}
func TestDao4_B23_EventFields(t *testing.T) {
	for _, recovered := range []bool{false, true} {
		for _, nulls := range []bool{false, true} {
			for _, kind := range []string{"confirmed", "updated", "type_upgrade", "evicted", "expired_get_failed", "expired_get_success"} {
				if recovered && kind == "confirmed" {
					continue
				} // RecoverFromDB never emits confirmed.
				name := "fresh/"
				if recovered {
					name = "recovered/"
				}
				if nulls {
					name += "nulls/"
				} else {
					name += "populated/"
				}
				t.Run(name+kind, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						ms := NewMockStore()
						ms.responses.responses = []store.Response{{ID: 1, Enabled: true}}
						var events []tracker.AttackEvent
						tk := dao4Tracker(dao4AttackStore{ms, kind == "expired_get_failed"}, func(e tracker.AttackEvent) {
							cp := snapshotAttack(*e.Attack)
							e.Attack = &cp
							events = append(events, e)
						})
						want := store.Attack{ID: 1, DstIP: "192.0.2.10", Direction: "receives", DecoderFamily: "udp", PrefixID: intPtr(7), ThresholdRuleID: intPtr(8), AttackType: "udp_flood", Severity: "medium", Confidence: 0.9, PeakPPS: 25001, PeakBPS: 800000, ReasonCodes: []string{"udp_exceeded"}, NodeSources: []string{"n1"}, ResponseID: intPtr(1), StartedAt: time.Now()}
						if nulls {
							want.PrefixID = nil
							want.ThresholdRuleID = nil
							want.ResponseID = nil
						}
						if recovered {
							want.Confidence = 0.73
							ms.attacks.appendAttacks(want)
							if err := tk.RecoverFromDB(context.Background()); err != nil {
								t.Fatal(err)
							}
							if len(events) != 0 {
								t.Fatal("recovery emitted an event")
							}
						} else {
							tk.Feed(dao4Threshold(nulls))
						}
						switch kind {
						case "updated":
							dao4Tick(tk, dao4Threshold(nulls))
						case "type_upgrade", "expired_get_success":
							tk.UpgradeType(net.ParseIP(want.DstIP), "dns_amp", 0.77, []string{"classified"})
							want.AttackType = "dns_amp"
							want.Confidence = 0.77
							want.ReasonCodes = append(want.ReasonCodes, "classified")
							row, err := ms.Attacks().Get(context.Background(), 1)
							if err != nil {
								t.Fatal(err)
							}
							if !reflect.DeepEqual(row.ResponseID, want.ResponseID) {
								t.Errorf("UpgradeType persisted ResponseID=%v; want %v", row.ResponseID, want.ResponseID)
							}
						}
						if kind == "evicted" {
							dao4Evict(tk)
							now := time.Now()
							want.EndedAt = &now
							want.ReasonCodes = append(want.ReasonCodes, "evicted_by_cap")
						}
						if kind == "expired_get_success" || kind == "expired_get_failed" {
							if !tk.ForceExpire(1) {
								t.Fatal("ForceExpire did not find attack")
							}
							now := time.Now()
							want.EndedAt = &now
							row, _ := ms.Attacks().Get(context.Background(), 1)
							if row.Confidence != want.Confidence {
								t.Errorf("expired persisted Confidence=%v; want %v", row.Confidence, want.Confidence)
							}
						}
						eventKind := kind
						if kind == "expired_get_success" || kind == "expired_get_failed" {
							eventKind = "expired"
						}
						var got *store.Attack
						count := 0
						for _, e := range events {
							if e.Type == eventKind && e.DBID == 1 {
								got = e.Attack
								count++
							}
						}
						if count != 1 {
							t.Fatalf("%s events=%d; want 1", eventKind, count)
						}
						if actual := dao4AttackFields(*got); !reflect.DeepEqual(actual, want) {
							t.Fatalf("%s fields\ngot  %+v\nwant %+v", eventKind, actual, want)
						}
					})
				})
			}
		}
	}
}
func TestDao4_B17_RecoveredUpdatedFields(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := NewMockStore()
		want := store.Attack{ID: 1, DstIP: "192.0.2.10", Direction: "receives", DecoderFamily: "udp", PrefixID: intPtr(7), ThresholdRuleID: intPtr(8), Confidence: 0.73, StartedAt: time.Now()}
		ms.attacks.appendAttacks(want)
		var got *store.Attack
		tk := dao4Tracker(ms, func(e tracker.AttackEvent) {
			if e.Type == "updated" {
				got = e.Attack
			}
		})
		if err := tk.RecoverFromDB(context.Background()); err != nil {
			t.Fatal(err)
		}
		dao4Tick(tk, dao4Threshold(false))
		if got == nil || !reflect.DeepEqual(got.PrefixID, want.PrefixID) || !reflect.DeepEqual(got.ThresholdRuleID, want.ThresholdRuleID) || got.Confidence != want.Confidence {
			t.Fatalf("recovered updated=%+v; want prefix=7 threshold=8 confidence=.73", got)
		}
	})
}
func TestDao4_B14_UpdatedWebhookPayload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, e, _ := dao4Fixture("webhook", "periodic", "on_detected")
		var mu sync.Mutex
		var payloads []map[string]any
		d.handler = func(r *http.Request) int {
			var p map[string]any
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				return 500
			}
			mu.Lock()
			payloads = append(payloads, p)
			mu.Unlock()
			return 200
		}
		tk := dao4Tracker(ms, e.HandleEvent)
		tk.Feed(dao4Threshold(false))
		synctest.Wait()
		dao4Tick(tk, dao4Threshold(false))
		synctest.Wait()
		mu.Lock()
		defer mu.Unlock()
		if len(payloads) != 2 {
			t.Fatalf("payload count=%d; want 2", len(payloads))
		}
		for key, want := range map[string]string{"dst_ip": "192.0.2.10", "decoder": "udp"} {
			values := make([]string, len(payloads))
			for i, payload := range payloads {
				value, exists := payload[key]
				str, isString := value.(string)
				if !exists || !isString || str == "" {
					t.Fatalf("payload %d key %s: exists=%v value=%#v; want nonempty string", i, key, exists, value)
				}
				values[i] = str
				if str != want {
					t.Errorf("payload %d %s=%q; want seed %q", i, key, str, want)
				}
			}
			if values[1] != values[0] {
				t.Errorf("%s confirmed=%q updated=%q", key, values[0], values[1])
			}
		}
	})
}
func TestDao4_B15_UpgradeExecutesPeriodicAction(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, e, _ := dao4Fixture("webhook", "periodic", "on_detected")
		tk := dao4Tracker(ms, e.HandleEvent)
		tk.Feed(dao4Threshold(false))
		synctest.Wait()
		tk.UpgradeType(net.ParseIP("192.0.2.10"), "dns_amp", 0.77, []string{"classified"})
		synctest.Wait()
		dao4WantCount(t, d, 2)
	})
}
func TestDao4_B16_EvictionUnblocksAndPreservesResponse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, _, e, _ := dao4XDrop()
		tk := dao4Tracker(ms, e.HandleEvent)
		tk.Feed(dao4Threshold(false))
		synctest.Wait()
		dao4Evict(tk)
		synctest.Wait()
		row, err := ms.Attacks().Get(context.Background(), 1)
		if err != nil {
			t.Fatal(err)
		}
		if row.ResponseID == nil || *row.ResponseID != 1 {
			t.Errorf("evicted ResponseID=%v; want 1", row.ResponseID)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		deletes := 0
		for _, r := range d.requests {
			if r.Method == "DELETE" && r.URL.Query().Get("claim_ref") == "a1.x10" {
				deletes++
			}
		}
		if deletes != 1 {
			t.Fatalf("eviction DELETEs=%d; want 1", deletes)
		}
	})
}
