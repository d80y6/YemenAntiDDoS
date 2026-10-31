package tracker

import (
	"context"
	"net"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/engine"
	"github.com/littlewolf9527/xsight/controller/internal/engine/dedup"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type dao13aRecoveryStore struct {
	*dao6Store
	rows []store.Attack
}
type dao13aRecoveryRepo struct {
	store.AttackRepo
	rows []store.Attack
}

func (s *dao13aRecoveryStore) Attacks() store.AttackRepo {
	return dao13aRecoveryRepo{s.dao6Store.Attacks(), s.rows}
}
func (r dao13aRecoveryRepo) ListActive(context.Context, int) ([]store.Attack, error) {
	return r.rows, nil
}
func (r dao13aRecoveryRepo) CountActive(context.Context) (int, error) { return len(r.rows), nil }
func (r dao13aRecoveryRepo) ListAllActive(context.Context) ([]store.Attack, error) {
	return r.rows, nil
}

func TestDao13a_B1_DedupCanonical(t *testing.T) {
	for _, tc := range []struct{ address, key string }{
		{"192.0.2.10/32", "192.0.2.10"},
		{"2001:db8::10/128", "2001:db8::10"},
		{"::ffff:192.0.2.10/128", "192.0.2.10"},
		{"::ffff:c000:20a/128", "192.0.2.10"},
	} {
		for _, mode := range []string{"Natural", "ForceExpire", "Eviction"} {
			t.Run(tc.address+"/"+mode, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ip := net.ParseIP(tc.key)
					d := dedup.New()
					s := &dao13aRecoveryStore{dao6Store: &dao6Store{next: 10}, rows: []store.Attack{
						{ID: 7, DstIP: tc.address, Direction: "receives", DecoderFamily: "udp", Severity: "low", StartedAt: time.Now().Add(-time.Hour)},
					}}
					tk := New(Config{HardConfirmSeconds: 1, MaxActiveAttacks: 2, ExpiryIntervalSeconds: 10}, s, nil, d, nil)
					if err := tk.RecoverFromDB(context.Background()); err != nil {
						t.Fatal(err)
					}
					probe := engine.ThresholdExceeded{DstIP: ip, Direction: "receives", Decoder: "ip"}
					if !d.ShouldSuppress(probe) {
						t.Error("canonical narrow registration did not suppress a new wide event")
					}
					// No concurrent operations: inspect keys read-only to exclude residual CIDR aliases.
					keys := reflect.ValueOf(d).Elem().FieldByName("active").MapKeys()
					if len(keys) != 1 || keys[0].FieldByName("DstIP").String() != tc.key {
						t.Errorf("registration is not a single canonical key: %v", keys)
					}
					feed := func(rows ...engine.ThresholdExceeded) {
						var filtered []engine.ThresholdExceeded
						for _, row := range rows {
							if !d.ShouldSuppress(row) {
								filtered = append(filtered, row)
							}
						}
						tk.Feed(filtered)
					}
					switch mode {
					case "Natural":
						feed()
						<-time.NewTimer(11 * time.Second).C
						feed()
					case "ForceExpire":
						if !tk.ForceExpire(7) {
							t.Fatal("recovered ID not found")
						}
					case "Eviction":
						feed(engine.ThresholdExceeded{DstIP: net.ParseIP("198.51.100.1"), Direction: "receives", Decoder: "udp", Unit: "pps", Actual: 200000},
							engine.ThresholdExceeded{DstIP: ip, Direction: "receives", Decoder: "udp"})
						feed(engine.ThresholdExceeded{DstIP: net.ParseIP("198.51.100.2"), Direction: "receives", Decoder: "udp", Unit: "pps", Actual: 2000000},
							engine.ThresholdExceeded{DstIP: ip, Direction: "receives", Decoder: "udp"})
						if tk.EvictedTotal.Load() != 1 {
							t.Fatal("eviction control did not run")
						}
					}
					if d.ShouldSuppress(probe) {
						t.Fatal("canonical registration survived removal")
					}
					for _, key := range reflect.ValueOf(d).Elem().FieldByName("active").MapKeys() {
						if got := key.FieldByName("DstIP").String(); got == tc.address || got == tc.key {
							t.Errorf("stale registration=%s", got)
						}
					}
				})
			})
		}
	}
}

func TestDao13a_B2_LiveSubnetHostPrefixKey(t *testing.T) {
	dao13aSubnetHostPrefixKey(t, false)
}

func TestDao13a_B2_RecoveredSubnetHostPrefixKey(t *testing.T) {
	dao13aSubnetHostPrefixKey(t, true)
}

func dao13aSubnetHostPrefixKey(t *testing.T, recovered bool) {
	t.Helper()
	for _, tc := range []struct{ prefix, key string }{
		{"192.0.2.10/32", "192.0.2.10"},
		{"2001:db8::10/128", "2001:db8::10"},
		{"::ffff:192.0.2.10/128", "192.0.2.10"},
		{"::ffff:c000:20a/128", "192.0.2.10"},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			d := dedup.New()
			s := &dao13aRecoveryStore{dao6Store: &dao6Store{next: 10}}
			events := map[string]int{}
			tk := New(Config{HardConfirmSeconds: 1, MaxActiveAttacks: 8}, s, nil, d, func(e AttackEvent) { events[e.Type]++ })
			wantID, wantCreates, wantPrefix := 11, 1, tc.prefix
			if recovered {
				s.rows = []store.Attack{{ID: 7, DstIP: tc.prefix, Direction: "receives", DecoderFamily: "udp",
					AttackType: "udp_flood", StartedAt: time.Now().Add(-time.Hour)}}
				if err := tk.RecoverFromDB(context.Background()); err != nil {
					t.Fatal(err)
				}
				// Recovery has no historical Prefix field; Feed must retain that empty value.
				wantID, wantCreates, wantPrefix = 7, 0, ""
			}
			subnet := engine.ThresholdExceeded{Domain: "subnet", Prefix: tc.prefix, Decoder: "udp", Direction: "receives", Unit: "pps", Actual: 20000}
			bare := subnet
			bare.DstIP, bare.Domain = net.ParseIP(tc.key), "internal_ip"
			for step, row := range []engine.ThresholdExceeded{subnet, subnet, bare} {
				var filtered []engine.ThresholdExceeded
				if !d.ShouldSuppress(row) {
					filtered = append(filtered, row)
				}
				tk.Feed(filtered)
				key := attackKey{tc.key, "receives", "udp"}
				a, ok := tk.attacks[key]
				if !ok || len(tk.attacks) != 1 {
					t.Fatalf("step %d canonical subnet key missing or duplicated: %v; want only %+v", step, tk.attacks, key)
				}
				if a.DBID != wantID || a.State != StateActive || a.Prefix != wantPrefix || a.Key != key {
					t.Errorf("step %d identity/prefix=%+v; want ID=%d key=%+v Prefix=%q", step, a, wantID, key, wantPrefix)
				}
				if creates := s.next - 10; creates != wantCreates || events["confirmed"] != wantCreates || events["expired"] != 0 {
					t.Errorf("step %d creates=%d confirmed=%d expired=%d; want creates/confirmed=%d expired=0",
						step, creates, events["confirmed"], events["expired"], wantCreates)
				}
			}
			probe := engine.ThresholdExceeded{DstIP: net.ParseIP(tc.key), Direction: "receives", Decoder: "ip"}
			keys := reflect.ValueOf(d).Elem().FieldByName("active").MapKeys()
			if len(keys) != 1 || keys[0].FieldByName("DstIP").String() != tc.key || !d.ShouldSuppress(probe) {
				t.Errorf("subnet dedup registration=%v; want one canonical narrow key %q", keys, tc.key)
			}
			if !tk.ForceExpire(wantID) {
				t.Fatalf("original subnet DBID %d could not be expired", wantID)
			}
			if len(tk.attacks) != 0 || reflect.ValueOf(d).Elem().FieldByName("active").Len() != 0 || d.ShouldSuppress(probe) || events["expired"] != 1 {
				t.Errorf("subnet removal left tracker/dedup state or missed expiry: attacks=%v events=%v", tk.attacks, events)
			}
		})
	}
}

func TestDao13a_G2_CanonicalHelper(t *testing.T) {
	for input, want := range map[string]string{
		"192.0.2.10/32": "192.0.2.10", "2001:0db8::10/128": "2001:db8::10",
		"192.0.2.10": "192.0.2.10", "invalid": "invalid", "192.0.2.10/24": "192.0.2.10/24",
		"::ffff:192.0.2.10/128": "192.0.2.10", "::ffff:c000:20a/128": "192.0.2.10",
		"::ffff:192.0.2.10/120": "::ffff:192.0.2.10/120", "::ffff:c000:20a/120": "::ffff:c000:20a/120",
	} {
		if got := canonicalHostKey(input); got != want {
			t.Errorf("canonicalHostKey(%q)=%q; want %q", input, got, want)
		}
	}
}
