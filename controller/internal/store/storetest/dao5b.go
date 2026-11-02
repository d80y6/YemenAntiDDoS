package storetest

import (
	"errors"
	"reflect"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// Dao5bBackend changes fixture generation independently of lifecycle methods.
type Dao5bBackend interface {
	FuzhuoBackend
	SetGeneration(id, gen int) error
}

func dao5bCurrentGen(t *testing.T, r store.BGPAnnouncementRepo, id int) int {
	t.Helper()
	a, err := r.Get(ctx, id)
	check(t, err)
	if a == nil {
		t.Fatalf("missing announcement %d", id)
	}
	return a.Gen
}

func dao5bSeed(t *testing.T, b Dao5bBackend, status string, count int) (store.BGPAnnouncementRepo, int) {
	t.Helper()
	s, id, _ := fuzhuoSeed(t, b, false, false)
	check(t, b.SetAnnouncement(id, count, status))
	check(t, b.SetGeneration(id, 7))
	return s.BGPAnnouncements(), id
}

func RunDao5bG3(t *testing.T, open func(*testing.T) Dao5bBackend) {
	type cell struct {
		op, status   string
		ref, gen     int
		hit, deleted bool
		seedGen0     bool
	}
	var cells []cell
	for _, op := range []string{"announced", "withdrawn", "failed_withdraw", "withdrawing", "failed_announce"} {
		allowed := map[string]bool{}
		switch op {
		case "announced":
			allowed["announcing"] = true
		case "withdrawing":
			allowed["delayed"] = true
		case "failed_announce":
			for _, s := range []string{"announcing", "active", "delayed", "withdrawing"} {
				allowed[s] = true
			}
		default:
			for _, s := range []string{"withdrawing", "delayed", "failed"} {
				allowed[s] = true
			}
		}
		for _, s := range []string{"announcing", "active", "delayed", "withdrawing", "withdrawn", "failed", "orphan", "dismissed", "dismissed_on_upgrade"} {
			ref := 2
			if s == "delayed" {
				ref = 0
			}
			cells = append(cells, cell{op, s, ref, 7, allowed[s], false, false})
		}
		wrongState := "announcing"
		if op == "withdrawing" {
			wrongState = "delayed"
		}
		if op == "withdrawn" || op == "failed_withdraw" {
			wrongState = "withdrawing"
		}
		cells = append(cells, cell{op, wrongState, 2, 6, false, false, false})
	}
	cells = append(cells, cell{"failed_announce", "announcing", 1, 7, true, false, false}, cell{"failed_announce", "announcing", 1, 0, true, true, true}, cell{"failed_announce", "announcing", 1, 6, false, false, false}, cell{"failed_announce", "active", 1, 7, true, false, false}, cell{"failed_announce", "withdrawing", 1, 7, true, false, false})
	for _, c := range cells {
		name := c.op + "/" + c.status
		if c.gen != 7 && !c.seedGen0 {
			name += "_wrong_gen"
		}
		if c.ref == 1 {
			name += "_ref1"
		}
		if c.seedGen0 {
			name += "_gen0"
		}
		t.Run(name, func(t *testing.T) {
			b := open(t)
			r, id := dao5bSeed(t, b, c.status, c.ref)
			if c.seedGen0 {
				check(t, b.SetGeneration(id, 0))
			}
			before, err := r.Get(ctx, id)
			check(t, err)
			events, err := r.ListEvents(ctx, id)
			check(t, err)
			var claimed bool
			switch c.op {
			case "announced":
				err = r.MarkAnnounced(ctx, id, c.gen)
			case "withdrawn":
				err = r.MarkWithdrawn(ctx, id, c.gen)
			case "failed_withdraw":
				err = r.MarkFailedWithdraw(ctx, id, c.gen, "G3 failure")
			case "withdrawing":
				claimed, err = r.MarkWithdrawing(ctx, id, c.gen)
			case "failed_announce":
				err = r.MarkFailedAnnounce(ctx, id, c.gen, "G3 failure")
			}
			t.Run("outcome", func(t *testing.T) {
				if c.op == "withdrawing" {
					if err != nil || claimed != c.hit {
						t.Errorf("claim=%v err=%v; want hit=%v", claimed, err, c.hit)
					}
				} else if c.hit {
					if err != nil {
						t.Errorf("hit returned %v", err)
					}
				} else if !errors.Is(err, store.ErrStaleAnnouncement) {
					t.Errorf("err=%v; want ErrStaleAnnouncement", err)
				}
			})
			after, err := r.Get(ctx, id)
			check(t, err)
			later, err := r.ListEvents(ctx, id)
			check(t, err)
			if !c.hit {
				t.Run("row_unchanged", func(t *testing.T) {
					if !reflect.DeepEqual(before, after) {
						t.Errorf("rejected write changed row: before=%+v after=%+v", before, after)
					}
				})
				t.Run("events_unchanged", func(t *testing.T) {
					if len(later) != len(events) {
						t.Errorf("rejected write event delta=%d; want 0", len(later)-len(events))
					}
				})
				return
			}
			if c.deleted {
				attachments, err := r.ListAttacks(ctx, id)
				check(t, err)
				if after != nil || len(later) != 0 || len(attachments) != 0 {
					t.Errorf("delete cascade: row=%+v events=%d attachments=%d", after, len(later), len(attachments))
				}
				return
			}
			want := map[string]string{"announced": "active", "withdrawn": "withdrawn", "failed_withdraw": "failed", "failed_announce": "failed", "withdrawing": "withdrawing"}[c.op]
			t.Run("row", func(t *testing.T) {
				if after == nil || after.Status != want {
					t.Fatalf("row=%+v; want status=%s", after, want)
				}
				if after.Gen != 7 {
					t.Errorf("within-generation write changed gen=%d; want 7", after.Gen)
				}
				if (c.op == "failed_withdraw" || c.op == "failed_announce") && after.ErrorMessage != "G3 failure" {
					t.Errorf("error_message=%q", after.ErrorMessage)
				}
			})
			delta := 1
			if c.op == "withdrawing" {
				delta = 0
			}
			t.Run("events", func(t *testing.T) {
				if len(later)-len(events) != delta {
					t.Errorf("event delta=%d; want %d", len(later)-len(events), delta)
				}
			})
		})
	}
}

func RunDao5bG2(t *testing.T, open func(*testing.T) Dao5bBackend) {
	cases := []struct {
		name, status string
		bump         bool
	}{
		{"resurrect_withdrawn", "withdrawn", true}, {"resurrect_failed", "failed", true},
		{"force_active", "active", true}, {"force_withdrawing", "withdrawing", true},
		{"orphan", "withdrawn", true}, {"dismissed_on_upgrade", "withdrawn", true},
		{"attach_delayed", "delayed", false}, {"force_withdrawn", "withdrawn", false}, {"force_dismissed", "dismissed", false},
		{"detach_active_zero", "active", false}, {"detach_active_delay", "active", false},
		{"detach_announcing_zero", "announcing", false}, {"detach_announcing_delay", "announcing", false},
		{"reconcile_up", "active", false}, {"reconcile_detach", "active", false},
		{"announced", "announcing", false}, {"withdrawing", "delayed", false}, {"dismiss", "orphan", false}, {"undismiss", "dismissed", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := open(t)
			r, id := dao5bSeed(t, b, c.status, 2)
			a, err := r.Get(ctx, id)
			check(t, err)
			rows, err := r.ListAttacks(ctx, id)
			check(t, err)
			p := store.BGPAttachParams{Prefix: a.Prefix, RouteMap: a.RouteMap, ConnectorID: a.ConnectorID, AttackID: rows[0].AttackID}
			switch c.name {
			case "resurrect_withdrawn", "resurrect_failed", "attach_delayed":
				_, err = r.Attach(ctx, p)
			case "force_active", "force_withdrawing", "force_withdrawn", "force_dismissed":
				_, _, err = r.ForceWithdraw(ctx, id)
			case "orphan", "dismissed_on_upgrade":
				_, err = r.UpsertOrphan(ctx, a.Prefix, a.RouteMap, a.ConnectorID, c.name)
			case "detach_active_zero", "detach_active_delay", "detach_announcing_zero", "detach_announcing_delay":
				if c.name == "detach_active_delay" || c.name == "detach_announcing_delay" {
					p.DelayMinutes = 1
					_, err = r.Attach(ctx, p)
					check(t, err)
				}
				check(t, b.SetAnnouncement(id, 1, c.status))
				_, err = r.Detach(ctx, p.AttackID, p.Prefix, p.RouteMap, p.ConnectorID)
			case "reconcile_up":
				check(t, b.SetAnnouncement(id, 1, c.status))
				_, err = r.ReconcileAttachments(ctx, id, nil, false)
			case "reconcile_detach":
				_, err = r.ReconcileAttachments(ctx, id, []int{rows[0].AttackID, rows[1].AttackID}, true)
			case "announced":
				err = r.MarkAnnounced(ctx, id, 7)
			case "withdrawing":
				_, err = r.MarkWithdrawing(ctx, id, 7)
			case "dismiss":
				err = r.Dismiss(ctx, id)
			case "undismiss":
				err = r.Undismiss(ctx, id)
			}
			check(t, err)
			after, err := r.Get(ctx, id)
			check(t, err)
			want := 7
			if c.bump {
				want++
			}
			if after.Gen != want {
				t.Errorf("gen=%d; want %d", after.Gen, want)
			}
		})
	}
}

func RunDao5bG4(t *testing.T, open func(*testing.T) Dao5bBackend) {
	for _, name := range []string{"attach_shared", "attach_idempotent", "attach_revive", "attach_delayed", "detach_shared", "detach_zero", "detach_delay", "detach_idempotent", "reconcile_up", "reconcile_detach", "reconcile_consistent", "reconcile_status", "reconcile_overcount", "force", "force_noop", "force_dismissed"} {
		t.Run(name, func(t *testing.T) {
			b := open(t)
			r, id := dao5bSeed(t, b, "active", 2)
			a, err := r.Get(ctx, id)
			check(t, err)
			rows, err := r.ListAttacks(ctx, id)
			check(t, err)
			p := store.BGPAttachParams{Prefix: a.Prefix, RouteMap: a.RouteMap, ConnectorID: a.ConnectorID, AttackID: rows[0].AttackID}
			var got int
			switch name {
			case "attach_shared", "attach_idempotent", "attach_revive", "attach_delayed":
				if name == "attach_shared" {
					p.AttackID = seedAttack(t, b.Store(), store.Attack{})
				}
				if name == "attach_revive" {
					check(t, b.SetAnnouncement(id, 0, "withdrawn"))
				}
				if name == "attach_delayed" {
					check(t, b.SetAnnouncement(id, 0, "delayed"))
				}
				v, e := r.Attach(ctx, p)
				err = e
				got = v.Gen
			case "detach_shared", "detach_zero", "detach_delay", "detach_idempotent":
				if name == "detach_zero" || name == "detach_delay" {
					check(t, b.SetAnnouncement(id, 1, "active"))
				}
				if name == "detach_delay" {
					p.DelayMinutes = 1
					_, err = r.Attach(ctx, p)
					check(t, err)
				}
				if name == "detach_idempotent" {
					p.AttackID = 999999
				}
				v, e := r.Detach(ctx, p.AttackID, p.Prefix, p.RouteMap, p.ConnectorID)
				err = e
				got = v.Gen
			case "force", "force_noop", "force_dismissed":
				if name == "force_noop" {
					check(t, b.SetAnnouncement(id, 0, "withdrawn"))
				}
				if name == "force_dismissed" {
					check(t, b.SetAnnouncement(id, 0, "dismissed"))
				}
				_, got, err = r.ForceWithdraw(ctx, id)
			default:
				if name == "reconcile_up" {
					check(t, b.SetAnnouncement(id, 1, "active"))
				}
				if name == "reconcile_status" {
					check(t, b.SetAnnouncement(id, 2, "failed"))
				}
				if name == "reconcile_overcount" {
					check(t, b.SetAnnouncement(id, 3, "active"))
				}
				detach := name != "reconcile_up"
				var ended []int
				if name == "reconcile_detach" {
					ended = []int{rows[0].AttackID, rows[1].AttackID}
				}
				v, e := r.ReconcileAttachments(ctx, id, ended, detach)
				err = e
				got = v.Gen
			}
			check(t, err)
			after, err := r.Get(ctx, id)
			check(t, err)
			if got != after.Gen || got == 0 {
				t.Errorf("result Gen=%d; stored nonzero Gen=%d", got, after.Gen)
			}
		})
	}
}

type Dao5bMigrationBackend interface {
	Dao5bBackend
	PrepareLegacy() (int, error)
	HasGen() (bool, error)
	Migrate() error
}

func RunDao5bG1(t *testing.T, b Dao5bMigrationBackend) {
	id, err := b.PrepareLegacy()
	check(t, err)
	exists, err := b.HasGen()
	check(t, err)
	equal(t, exists, false)
	check(t, b.Migrate())
	exists, err = b.HasGen()
	check(t, err)
	if !exists {
		t.Fatal("gen column does not exist after AutoMigrate")
	}
	r := b.Store().BGPAnnouncements()
	a, err := r.Get(ctx, id)
	check(t, err)
	equal(t, a.Gen, 0)
	for _, list := range []func() ([]store.BGPAnnouncement, error){func() ([]store.BGPAnnouncement, error) { return r.ListActive(ctx) }, func() ([]store.BGPAnnouncement, error) { return r.ListByStatus(ctx, "active") }} {
		rows, err := list()
		check(t, err)
		if len(rows) != 1 || rows[0].Gen != 0 {
			t.Fatalf("legacy list=%+v", rows)
		}
	}
	check(t, b.SetAnnouncement(id, 0, "dismissed"))
	rows, err := r.ListDismissed(ctx)
	check(t, err)
	if len(rows) != 1 || rows[0].Gen != 0 {
		t.Fatalf("dismissed list=%+v", rows)
	}
	check(t, b.SetGeneration(id, 9))
	check(t, b.Migrate())
	a, err = r.Get(ctx, id)
	check(t, err)
	equal(t, a.Gen, 9)
}
