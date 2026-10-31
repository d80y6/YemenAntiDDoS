package tests

import (
	"context"
	"net"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/engine"
	"github.com/littlewolf9527/xsight/controller/internal/engine/classifier"
	"github.com/littlewolf9527/xsight/controller/internal/engine/dedup"
	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

type dao13aFixture struct {
	s      *dao5AttackStore
	tk     *tracker.Tracker
	d      *dedup.Dedup
	events []tracker.AttackEvent
}

func dao13aNew(capacity int) *dao13aFixture {
	ms := NewMockStore()
	f := &dao13aFixture{d: dedup.New()}
	f.s = &dao5AttackStore{MockStore: ms, r: &dao5Attacks{AttackRepo: ms.Attacks()}}
	f.tk = tracker.New(tracker.Config{HardConfirmSeconds: 1, DynamicConfirmSeconds: 1,
		ExpiryIntervalSeconds: 10, MaxActiveAttacks: capacity}, f.s, nil, f.d,
		func(e tracker.AttackEvent) { f.events = append(f.events, e) })
	return f
}

func dao13aEvent(address, decoder, direction string) engine.ThresholdExceeded {
	return engine.ThresholdExceeded{DstIP: net.ParseIP(address), Prefix: "192.0.2.0/24",
		Direction: direction, Decoder: decoder, Domain: "internal_ip", Unit: "pps", Actual: 20000}
}

// Match main: filter the complete batch against the previous registration state,
// then feed exactly once, including an empty batch.
func (f *dao13aFixture) feed(advance bool, rows ...engine.ThresholdExceeded) []engine.ThresholdExceeded {
	var filtered []engine.ThresholdExceeded
	for _, row := range rows {
		if !f.d.ShouldSuppress(row) {
			filtered = append(filtered, row)
		}
	}
	if advance {
		dao4Tick(f.tk, filtered)
	} else {
		f.tk.Feed(filtered)
	}
	return filtered
}

func (f *dao13aFixture) count(kind string) int {
	n := 0
	for _, e := range f.events {
		if e.Type == kind {
			n++
		}
	}
	return n
}

func (f *dao13aFixture) recover(t *testing.T, rows ...store.Attack) {
	t.Helper()
	f.s.attacks.appendAttacks(rows...)
	if err := f.tk.RecoverFromDB(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func dao13aSeed(id int, address, decoder, direction string) store.Attack {
	return store.Attack{ID: id, DstIP: address, Direction: direction, DecoderFamily: decoder,
		AttackType: decoder + "_flood", Severity: "medium", PeakPPS: 20000,
		StartedAt: time.Now().Add(-time.Hour)}
}

func dao13aStable(t *testing.T, f *dao13aFixture, ids ...int) {
	t.Helper()
	timers := f.tk.ActiveTimers()
	if len(timers) != len(ids) || f.tk.ActiveCount() != len(ids) {
		t.Errorf("live identities=%v count=%d; want IDs %v", timers, f.tk.ActiveCount(), ids)
	}
	for _, id := range ids {
		if timer, ok := timers[id]; !ok || timer.State != tracker.StateActive {
			t.Errorf("original ID %d is not active: %+v", id, timers)
		}
	}
}

func dao13aRunWide(t *testing.T) (*dao13aFixture, engine.ThresholdExceeded, engine.ThresholdExceeded, []int) {
	t.Helper()
	f := dao13aNew(8)
	wide := dao13aEvent("192.0.2.10", "ip", "receives")
	narrow := dao13aEvent("192.0.2.10", "udp", "receives")
	f.feed(false, wide, narrow)
	var ids []int
	for _, e := range f.events {
		if e.Type == "confirmed" {
			ids = append(ids, e.DBID)
		}
	}
	if len(ids) != 2 {
		t.Fatalf("initial confirmations=%v; want two", ids)
	}
	for i := 0; i < 5; i++ {
		f.feed(true, wide, narrow)
	}
	return f, wide, narrow, ids
}

func TestDao13a_A1(t *testing.T) {
	for _, name := range []string{"WideKeepsOriginalID", "NoExpiredWhileBothBreach", "WideStops"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, _, narrow, ids := dao13aRunWide(t)
				if name == "NoExpiredWhileBothBreach" {
					if n := f.count("expired"); n != 0 {
						t.Fatalf("expired while both breach=%d; want zero", n)
					}
					return
				}
				dao13aStable(t, f, ids...)
				if n := f.count("confirmed"); n != 2 {
					t.Fatalf("confirmed=%d; want exactly two", n)
				}
				if name == "WideStops" {
					f.feed(true, narrow)
					f.feed(true, narrow)
					if f.count("expired") != 1 || f.tk.ActiveCount() != 1 {
						t.Fatalf("wide stop: expired=%d active=%d", f.count("expired"), f.tk.ActiveCount())
					}
					for _, e := range f.events {
						if e.Type == "expired" && e.Attack.DecoderFamily != "ip" {
							t.Error("narrow attack expired while still breaching")
						}
					}
				}
			})
		})
	}
}

func TestDao13a_A2(t *testing.T) {
	t.Run("ConfirmingHasNoExemption", func(t *testing.T) {
		f := dao13aNew(8)
		f.tk = tracker.New(tracker.Config{HardConfirmSeconds: 2, MaxActiveAttacks: 8}, f.s, nil, f.d,
			func(e tracker.AttackEvent) { f.events = append(f.events, e) })
		narrow, wide := dao13aEvent("192.0.2.10", "udp", "receives"), dao13aEvent("192.0.2.10", "ip", "receives")
		f.feed(false, narrow)
		f.feed(false, narrow, wide)
		if !f.d.ShouldSuppress(wide) {
			t.Fatal("confirming wide attack incorrectly received an exemption")
		}
		f.feed(false, narrow, wide)
		if f.count("confirmed") != 1 || f.tk.ActiveCount() != 1 {
			t.Fatal("confirming wide attack survived narrow registration")
		}
	})
	t.Run("NarrowOnlySuppressesNewWide", func(t *testing.T) {
		f := dao13aNew(8)
		narrow := dao13aEvent("192.0.2.10", "udp", "receives")
		wide := dao13aEvent("192.0.2.10", "ip", "receives")
		f.feed(false, narrow)
		for i := 0; i < 3; i++ {
			filtered := f.feed(false, wide, narrow)
			if len(filtered) != 1 || filtered[0].Decoder != "udp" {
				t.Errorf("new broad event reached Feed: %+v", filtered)
			}
		}
		if f.count("confirmed") != 1 || f.tk.ActiveCount() != 1 {
			t.Error("new wide attack was created")
		}
	})
	t.Run("TCPAndSYN", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := dao13aNew(8)
			wide := dao13aEvent("192.0.2.10", "tcp", "receives")
			narrow := dao13aEvent("192.0.2.10", "tcp_syn", "receives")
			f.feed(false, wide, narrow)
			for i := 0; i < 4; i++ {
				f.feed(true, wide, narrow)
			}
			if f.count("expired") != 0 || f.count("confirmed") != 2 || f.tk.ActiveCount() != 2 {
				t.Error("TCP/SYN lifecycle diverged")
			}
		})
	})
	t.Run("OppositeDirection", func(t *testing.T) {
		f := dao13aNew(8)
		f.feed(false, dao13aEvent("192.0.2.10", "udp", "receives"))
		wide := dao13aEvent("192.0.2.10", "ip", "sends")
		if f.d.ShouldSuppress(wide) {
			t.Fatal("opposite direction was suppressed")
		}
		f.feed(false, wide)
		if f.count("confirmed") != 2 {
			t.Fatal("opposite direction did not confirm")
		}
	})
	t.Run("SubnetBypass", func(t *testing.T) {
		f := dao13aNew(8)
		f.feed(false, dao13aEvent("192.0.2.10", "udp", "receives"))
		row := dao13aEvent("192.0.2.10", "ip", "receives")
		row.DstIP, row.Domain, row.Prefix = nil, "subnet", "192.0.2.10/32"
		if f.d.ShouldSuppress(row) {
			t.Fatal("subnet event was suppressed")
		}
		f.feed(false, row)
		if f.count("confirmed") != 2 {
			t.Fatal("subnet event did not reach tracker")
		}
	})
	t.Run("ExpiringWideReturnsToActive", func(t *testing.T) {
		f := dao13aNew(8)
		wide, narrow := dao13aEvent("192.0.2.10", "ip", "receives"), dao13aEvent("192.0.2.10", "udp", "receives")
		f.feed(false, wide, narrow)
		ids := []int{f.events[0].DBID, f.events[1].DBID}
		f.feed(false, narrow)
		f.feed(false, wide, narrow)
		dao13aStable(t, f, ids...)
		if f.count("confirmed") != 2 || f.count("expired") != 0 {
			t.Fatal("rebreach replaced the original attack")
		}
	})
}

func TestDao13a_A3(t *testing.T) {
	for _, recovered := range []bool{false, true} {
		source := "Live"
		if recovered {
			source = "Recovered"
		}
		for _, mode := range []string{"Natural", "ForceExpire", "Eviction"} {
			t.Run(source+"/"+mode, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := dao13aNew(2)
					wide, narrow := dao13aEvent("192.0.2.10", "ip", "receives"), dao13aEvent("192.0.2.10", "udp", "receives")
					wide.Actual = 100
					wideID, narrowID := 0, 0
					if recovered {
						w := dao13aSeed(11, "192.0.2.10/32", "ip", "receives")
						w.PeakPPS, w.Severity = 100, "low"
						f.recover(t, w, dao13aSeed(12, "192.0.2.10/32", "udp", "receives"))
						wideID, narrowID = 11, 12
					} else {
						f.feed(false, wide, narrow)
						for _, e := range f.events {
							if e.Attack.DecoderFamily == "ip" {
								wideID = e.DBID
							} else {
								narrowID = e.DBID
							}
						}
					}
					if f.d.ShouldSuppress(wide) {
						t.Fatal("registered wide key did not exempt itself")
					}
					switch mode {
					case "Natural":
						f.feed(true, narrow)
						f.feed(true, narrow)
					case "ForceExpire":
						if !f.tk.ForceExpire(wideID) {
							t.Fatal("wide ID not found")
						}
					case "Eviction":
						replacement := dao13aEvent("192.0.2.99", "udp", "receives")
						replacement.Actual = 2000000
						f.feed(false, wide, narrow, replacement)
						if f.tk.EvictedTotal.Load() != 1 {
							t.Fatal("capacity pressure did not evict")
						}
					}
					if _, alive := f.tk.ActiveTimers()[wideID]; alive || !f.d.ShouldSuppress(wide) {
						t.Fatal("removed wide key retained its exemption")
					}
					if filtered := f.feed(false, wide, narrow); len(filtered) != 1 {
						t.Fatalf("wide was not suppressed after removal: %+v", filtered)
					}
					if !f.tk.ForceExpire(narrowID) || f.d.ShouldSuppress(wide) {
						t.Fatal("clearing narrow did not release new wide events")
					}
				})
			})
		}
	}
	t.Run("RecoveredNarrowSuppressesNewWide", func(t *testing.T) {
		for _, address := range []string{"192.0.2.10/32", "2001:db8::10/128"} {
			t.Run(address, func(t *testing.T) {
				ip, _, _ := net.ParseCIDR(address)
				f := dao13aNew(8)
				f.recover(t, dao13aSeed(7, address, "udp", "receives"))
				wide := dao13aEvent(ip.String(), "ip", "receives")
				if !f.d.ShouldSuppress(wide) || len(f.feed(false, wide)) != 0 {
					t.Fatal("recovered canonical narrow key did not suppress new wide event")
				}
			})
		}
	})
	t.Run("DelayedWideAfterNarrow", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := dao13aNew(8)
			f.recover(t, dao13aSeed(11, "192.0.2.10/32", "ip", "receives"), dao13aSeed(12, "192.0.2.10/32", "udp", "receives"))
			wide, narrow := dao13aEvent("192.0.2.10", "ip", "receives"), dao13aEvent("192.0.2.10", "udp", "receives")
			f.feed(false, narrow)
			for i := 0; i < 5; i++ {
				f.feed(true, wide, narrow)
			}
			dao13aStable(t, f, 11, 12)
			if f.count("expired") != 0 || f.count("confirmed") != 0 {
				t.Fatalf("delayed wide events=%+v", f.events)
			}
		})
	})
}

func TestDao13a_B1(t *testing.T) {
	for _, tc := range []struct{ name, address, liveIP string }{
		{"IPv4_NoCreateAndSameDBID", "192.0.2.10/32", "192.0.2.10"},
		{"IPv6_NoCreateAndSameDBID", "2001:db8::10/128", "2001:db8::10"},
		{"MappedDotted_NoCreateAndSameDBID", "::ffff:192.0.2.10/128", "192.0.2.10"},
		{"MappedHex_NoCreateAndSameDBID", "::ffff:c000:20a/128", "192.0.2.10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao13aNew(8)
				f.recover(t, dao13aSeed(7, tc.address, "udp", "receives"))
				for i := 0; i < 5; i++ {
					f.feed(true, dao13aEvent(tc.liveIP, "udp", "receives"))
				}
				dao13aStable(t, f, 7)
				creates, _ := f.s.r.counts()
				if creates != 0 || f.count("confirmed") != 0 || f.count("expired") != 0 {
					t.Errorf("creates=%d confirmed=%d expired=%d", creates, f.count("confirmed"), f.count("expired"))
				}
				ips := f.tk.ActiveDstIPs()
				if !reflect.DeepEqual(ips, []string{tc.liveIP}) || net.ParseIP(ips[0]) == nil {
					t.Errorf("classifier input=%v; want canonical IP %s", ips, tc.liveIP)
				}
			})
		})
	}
	t.Run("RecoveredClassifies", func(t *testing.T) {
		for _, address := range []string{"192.0.2.10/32", "2001:db8::10/128"} {
			t.Run(address, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := dao13aNew(8)
					f.recover(t, dao13aSeed(7, address, "udp", "receives"), dao13aSeed(8, address, "udp", "sends"))
					ip, _, _ := net.ParseCIDR(address)
					for i := 0; i < 3; i++ {
						f.feed(true, dao13aEvent(ip.String(), "udp", "receives"), dao13aEvent(ip.String(), "udp", "sends"))
						dao13aClassify(f, ip.String(), 20)
					}
					dao13aStable(t, f, 7, 8)
					dao13aWantTypes(t, f, map[int]string{7: "dns_reflection", 8: "udp_flood"}, 1)
					creates, _ := f.s.r.counts()
					if creates != 0 || f.count("confirmed") != 0 || f.count("expired") != 0 {
						t.Error("recovered classification replaced an identity")
					}
					for _, e := range f.events {
						if e.Type == "type_upgrade" && (e.DBID != 7 || e.Attack.DstIP != ip.String()) {
							t.Errorf("unexpected upgrade identity: %+v", e)
						}
					}
				})
			})
		}
	})
}

func TestDao13a_B2(t *testing.T) {
	for _, name := range []string{"SubnetHostCIDR_SameDBID", "SubnetStops_IPContinues"} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct{ address, key string }{
				{"192.0.2.10/32", "192.0.2.10"}, {"2001:db8::10/128", "2001:db8::10"},
				{"::ffff:192.0.2.10/128", "192.0.2.10"}, {"::ffff:c000:20a/128", "192.0.2.10"},
			} {
				t.Run(tc.address, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						f := dao13aNew(8)
						f.recover(t, dao13aSeed(7, tc.address, "udp", "receives"))
						row := dao13aEvent("", "udp", "receives")
						row.Domain, row.Prefix = "subnet", tc.address
						f.feed(true, row)
						if name == "SubnetStops_IPContinues" {
							row = dao13aEvent(tc.key, "udp", "receives")
						}
						for i := 0; i < 5; i++ {
							f.feed(true, row)
						}
						dao13aStable(t, f, 7)
						if !reflect.DeepEqual(f.tk.ActiveDstIPs(), []string{tc.key}) {
							t.Errorf("subnet continuation keys=%v; want only %q", f.tk.ActiveDstIPs(), tc.key)
						}
						creates, _ := f.s.r.counts()
						if creates != 0 || f.count("confirmed") != 0 || f.count("expired") != 0 {
							t.Errorf("creates=%d confirmed=%d expired=%d", creates, f.count("confirmed"), f.count("expired"))
						}
					})
				})
			}
		})
	}
	t.Run("HostPrefixRulesMerge", func(t *testing.T) {
		for _, subnetFirst := range []bool{true, false} {
			name := "IPFirst"
			if subnetFirst {
				name = "SubnetFirst"
			}
			t.Run(name, func(t *testing.T) {
				f := dao13aNew(8)
				f.s.responses.responses = []store.Response{{ID: 101, Enabled: true}, {ID: 102, Enabled: true}}
				ip := dao13aEvent("192.0.2.10", "udp", "receives")
				ip.Prefix, ip.ResponseID, ip.ThresholdID = "192.0.2.10/32", intPtr(101), 11
				subnet := ip
				subnet.DstIP, subnet.Domain, subnet.ResponseID, subnet.ThresholdID = nil, "subnet", intPtr(102), 12
				rows := []engine.ThresholdExceeded{ip, subnet}
				if subnetFirst {
					rows[0], rows[1] = rows[1], rows[0]
				}
				f.feed(false, rows...)
				f.feed(false, rows...)
				if f.count("confirmed") != 1 || f.tk.ActiveCount() != 1 {
					t.Fatalf("host rules did not merge: events=%+v", f.events)
				}
				e := f.events[0]
				if e.Attack.DstIP != "192.0.2.10" || !reflect.DeepEqual(e.Attack.ResponseID, rows[0].ResponseID) || e.Attack.ThresholdRuleID == nil || *e.Attack.ThresholdRuleID != rows[0].ThresholdID {
					t.Fatalf("first confirming writer did not own response: %+v", e.Attack)
				}
			})
		}
	})
	t.Run("NonHostPrefixUnchanged", func(t *testing.T) {
		for _, prefix := range []string{"192.0.2.0/24", "2001:db8::/64", "0.0.0.0/0", "::ffff:192.0.2.10/120", "::ffff:c000:20a/120"} {
			t.Run(prefix, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					for _, recovered := range []bool{true, false} {
						f := dao13aNew(8)
						if recovered {
							f.recover(t, dao13aSeed(7, prefix, "udp", "receives"))
						}
						row := dao13aEvent("", "udp", "receives")
						row.Domain, row.Prefix = "subnet", prefix
						for i := 0; i < 3; i++ {
							f.feed(true, row)
						}
						if !reflect.DeepEqual(f.tk.ActiveDstIPs(), []string{prefix}) || f.tk.ActiveCount() != 1 || f.count("expired") != 0 {
							t.Fatalf("non-host prefix changed: %v", f.tk.ActiveDstIPs())
						}
						if recovered {
							dao13aStable(t, f, 7)
							if n, _ := f.s.r.counts(); n != 0 {
								t.Fatalf("recovered prefix created %d new attacks", n)
							}
						}
					}
				})
			})
		}
	})
	t.Run("ConfigIndependent", func(t *testing.T) {
		for _, config := range []string{"RuleDomainChanged", "PrefixCIDRChanged", "BothMissing"} {
			t.Run(config, func(t *testing.T) {
				f := dao13aNew(8)
				s := &dao13aConfigStore{Store: f.s, mode: config}
				f.tk = tracker.New(tracker.Config{HardConfirmSeconds: 1, ExpiryIntervalSeconds: 10, MaxActiveAttacks: 8}, s, nil, f.d, func(e tracker.AttackEvent) { f.events = append(f.events, e) })
				seeds := []store.Attack{dao13aSeed(7, "192.0.2.10/32", "udp", "receives"), dao13aSeed(8, "2001:db8::10/128", "udp", "receives"), dao13aSeed(9, "192.0.2.0/24", "udp", "receives")}
				for i := range seeds {
					seeds[i].PrefixID, seeds[i].ThresholdRuleID = intPtr(17+i), intPtr(27+i)
				}
				f.recover(t, seeds...)
				got := f.tk.ActiveDstIPs()
				// Compare sets without imposing map iteration order.
				current := map[string]bool{}
				for _, ip := range got {
					current[ip] = true
				}
				want := map[string]bool{"192.0.2.10": true, "2001:db8::10": true, "192.0.2.0/24": true}
				if !reflect.DeepEqual(current, want) || s.lookups != 0 || f.count("confirmed") != 0 {
					t.Errorf("config=%s identities=%v lookups=%d", config, got, s.lookups)
				}
				subnet := dao13aEvent("", "udp", "receives")
				subnet.Domain, subnet.Prefix = "subnet", "192.0.2.0/24"
				f.feed(false, dao13aEvent("192.0.2.10", "udp", "receives"), dao13aEvent("2001:db8::10", "udp", "receives"), subnet)
				dao13aStable(t, f, 7, 8, 9)
				if creates, _ := f.s.r.counts(); creates != 0 {
					t.Fatalf("configuration-dependent recovery created %d attacks", creates)
				}
			})
		}
	})
}

type dao13aConfigStore struct {
	store.Store
	mode    string
	lookups int
}
type dao13aConfigThreshold struct {
	store.ThresholdRepo
	s *dao13aConfigStore
}
type dao13aConfigPrefix struct {
	store.PrefixRepo
	s *dao13aConfigStore
}

func (s *dao13aConfigStore) Thresholds() store.ThresholdRepo {
	s.lookups++
	return dao13aConfigThreshold{s.Store.Thresholds(), s}
}
func (s *dao13aConfigStore) Prefixes() store.PrefixRepo {
	s.lookups++
	return dao13aConfigPrefix{s.Store.Prefixes(), s}
}
func (r dao13aConfigThreshold) Get(ctx context.Context, id int) (*store.Threshold, error) {
	if r.s.mode == "BothMissing" {
		return r.ThresholdRepo.Get(ctx, id)
	}
	domain := "internal_ip"
	if r.s.mode == "RuleDomainChanged" {
		domain = "subnet"
	}
	return &store.Threshold{ID: id, Domain: domain}, nil
}
func (r dao13aConfigPrefix) Get(ctx context.Context, id int) (*store.WatchPrefix, error) {
	if r.s.mode == "BothMissing" {
		return r.PrefixRepo.Get(ctx, id)
	}
	prefix := "192.0.2.10/32"
	if r.s.mode == "PrefixCIDRChanged" {
		prefix = "192.0.2.0/24"
	}
	return &store.WatchPrefix{ID: id, Prefix: prefix}, nil
}

func dao13aClassify(f *dao13aFixture, address string, samples int) {
	c := classifier.New()
	batch := &pb.SampleBatch{}
	for i := 0; i < samples; i++ {
		batch.Samples = append(batch.Samples, &pb.PacketSample{DstIp: net.ParseIP(address), SrcPort: 53, IpProtocol: 17})
	}
	c.Ingest(batch)
	for _, address := range f.tk.ActiveDstIPs() {
		ip := net.ParseIP(address)
		if ip == nil {
			continue
		}
		if result := c.Classify(ip); result != nil {
			f.tk.UpgradeType(ip, result.AttackType, result.Confidence, result.Reasons)
		}
	}
}

func dao13aWantTypes(t *testing.T, f *dao13aFixture, want map[int]string, upgrades int) {
	t.Helper()
	for id, kind := range want {
		a, err := f.s.Attacks().Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if a.AttackType != kind {
			t.Errorf("ID %d type=%s; want %s", id, a.AttackType, kind)
		}
	}
	if n := f.count("type_upgrade"); n != upgrades {
		t.Errorf("type_upgrade count=%d; want %d", n, upgrades)
	}
}

func dao13aRequireActiveIdentities(t *testing.T, f *dao13aFixture, decoder, initialType string, directions []string) map[string]int {
	t.Helper()
	wantDirections := map[string]bool{}
	for _, direction := range directions {
		wantDirections[direction] = true
	}
	timers := f.tk.ActiveTimers()
	if confirmed, active := f.count("confirmed"), f.tk.ActiveCount(); confirmed != len(directions) || active != len(directions) || len(timers) != len(directions) {
		t.Fatalf("identity establishment: confirmed=%d active=%d timers=%d; want %d identities with directions %q",
			confirmed, active, len(timers), len(directions), directions)
	}
	ids := map[string]int{}
	for id, timer := range timers {
		a, err := f.s.Attacks().Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if timer.State != tracker.StateActive || a.DstIP != "192.0.2.10" || a.DecoderFamily != decoder || a.AttackType != initialType {
			t.Fatalf("identity establishment: ID %d timer=%+v attack=%+v; want active %s %s", id, timer, a, decoder, initialType)
		}
		if !wantDirections[a.Direction] || ids[a.Direction] != 0 {
			t.Fatalf("identity establishment: unexpected or duplicate direction %q in ID %d", a.Direction, id)
		}
		ids[a.Direction] = id
	}
	for _, direction := range directions {
		if _, ok := ids[direction]; !ok {
			t.Fatalf("identity establishment: missing direction %q", direction)
		}
	}
	return ids
}

func TestDao13a_D1(t *testing.T) {
	t.Run("OutboundIdentityEstablished", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			directions []string
		}{
			{"MixedDirections", []string{"receives", "sends"}},
			{"SendsOnly", []string{"sends"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := dao13aNew(8)
				var rows []engine.ThresholdExceeded
				for _, direction := range tc.directions {
					rows = append(rows, dao13aEvent("192.0.2.10", "udp", direction))
				}
				f.feed(false, rows...)
				dao13aRequireActiveIdentities(t, f, "udp", "udp_flood", tc.directions)
			})
		}
	})
	for _, tc := range []struct {
		name, decoder, initialType string
		directions                 []string
		finalTypes                 map[string]string
		upgrades, writes, samples  int
	}{
		{"ReceivesUpgraded", "udp", "udp_flood", []string{"receives", "sends"}, map[string]string{"receives": "dns_reflection", "sends": "udp_flood"}, 1, 1, 20},
		{"SendsUnchanged", "udp", "udp_flood", []string{"receives", "sends"}, map[string]string{"receives": "dns_reflection", "sends": "udp_flood"}, 1, 1, 20},
		{"EmptyDirectionUpgraded", "udp", "udp_flood", []string{""}, map[string]string{"": "dns_reflection"}, 1, 1, 20},
		{"SendsOnly", "udp", "udp_flood", []string{"sends"}, map[string]string{"sends": "udp_flood"}, 0, 0, 20},
		{"NonUDP", "tcp", "tcp_flood", []string{"receives"}, map[string]string{"receives": "tcp_flood"}, 0, 0, 20},
		{"Expiring", "udp", "udp_flood", []string{"receives"}, map[string]string{"receives": "udp_flood"}, 0, 0, 20},
		{"SameType", "udp", "udp_flood", []string{"receives"}, map[string]string{"receives": "dns_reflection"}, 1, 0, 20},
		{"InsufficientSamples", "udp", "udp_flood", []string{"receives"}, map[string]string{"receives": "udp_flood"}, 0, 0, 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := dao13aNew(8)
			var rows []engine.ThresholdExceeded
			for _, direction := range tc.directions {
				rows = append(rows, dao13aEvent("192.0.2.10", tc.decoder, direction))
			}
			f.feed(false, rows...)
			// Keep the same prerequisite before testing classification outcomes.
			idsByDirection := dao13aRequireActiveIdentities(t, f, tc.decoder, tc.initialType, tc.directions)
			want := map[int]string{}
			for _, direction := range tc.directions {
				id, ok := idsByDirection[direction]
				if !ok {
					t.Fatalf("classification precondition: missing direction %q", direction)
				}
				want[id] = tc.finalTypes[direction]
			}
			if tc.name == "Expiring" {
				f.feed(false)
				if timer := f.tk.ActiveTimers()[idsByDirection["receives"]]; timer.State != tracker.StateExpiring {
					t.Fatalf("expiring control did not enter Expiring: %+v", timer)
				}
			}
			if tc.name == "SameType" {
				dao13aClassify(f, "192.0.2.10", 20)
				dao13aWantTypes(t, f, want, 1)
			}
			_, before := f.s.r.counts()
			t.Log("classification reached after identity establishment")
			dao13aClassify(f, "192.0.2.10", tc.samples)
			_, after := f.s.r.counts()
			if after-before != tc.writes {
				t.Errorf("classification writes=%d; want %d", after-before, tc.writes)
			}
			dao13aWantTypes(t, f, want, tc.upgrades)
			for _, e := range f.events {
				if e.Type == "type_upgrade" {
					if e.Attack.Direction == "sends" || idsByDirection[e.Attack.Direction] != e.DBID || tc.finalTypes[e.Attack.Direction] != "dns_reflection" || e.Attack.AttackType != "dns_reflection" {
						t.Errorf("upgrade did not belong to the original inbound identity: %+v", e)
					}
				}
			}
		})
	}
}

func TestDao13a_R0_Fixed(t *testing.T) {
	t.Run("P1_05", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, _, _, ids := dao13aRunWide(t)
			dao13aStable(t, f, ids...)
			if f.count("expired") != 0 {
				t.Fatal("wide attack expired under sustained load")
			}
		})
	})
	t.Run("P1_06", func(t *testing.T) {
		f := dao13aNew(8)
		seed := dao13aSeed(7, "192.0.2.10/32", "udp", "receives")
		seed.ThresholdRuleID = intPtr(11)
		f.s.thresholdRepo.records = map[int]store.Threshold{11: {ID: 11, Domain: "internal_ip"}}
		f.recover(t, seed)
		f.feed(false, dao13aEvent("192.0.2.10", "udp", "receives"))
		dao13aStable(t, f, 7)
		if creates, _ := f.s.r.counts(); creates != 0 || f.count("confirmed") != 0 {
			t.Fatal("recovery created a duplicate attack")
		}
	})
	t.Run("B10", func(t *testing.T) {
		f := dao13aNew(8)
		f.feed(false, dao13aEvent("192.0.2.10", "udp", "receives"), dao13aEvent("192.0.2.10", "udp", "sends"))
		f.tk.UpgradeType(net.ParseIP("192.0.2.10"), "dns_reflection", .95, []string{"classified"})
		for _, e := range f.events {
			if e.Type == "type_upgrade" && e.Attack.Direction == "sends" {
				t.Fatal("outbound attack was upgraded")
			}
		}
		if f.count("type_upgrade") != 1 {
			t.Fatal("inbound control did not upgrade")
		}
	})
}
