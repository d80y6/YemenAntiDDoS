package storetest

import (
	"strings"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// FuzhuoBackend creates deliberately inconsistent rows without a production API.
type FuzhuoBackend interface {
	Backend
	SetAnnouncement(id, refcount int, status string) error
}

func fuzhuoSeed(t *testing.T, b Backend, ended ...bool) (store.Store, int, []int) {
	t.Helper()
	s := b.Store()
	resp := seedResponse(t, s, "fuzhuo")
	act := seedAction(t, s, resp)
	conn, err := s.BGPConnectors().Create(ctx, &store.BGPConnector{Name: "fuzhuo", Enabled: true, VtyshPath: "/usr/bin/true", BGPASN: 64512, AddressFamily: "ipv4 unicast"})
	check(t, err)
	var ids []int
	var ann int
	for _, end := range ended {
		a := store.Attack{}
		if end {
			a.EndedAt = ptr(stamp(50))
		}
		id := seedAttack(t, s, a)
		ids = append(ids, id)
		r, err := s.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{Prefix: "192.0.2.71/32", RouteMap: "RTBH", ConnectorID: conn, AttackID: id, ActionID: &act})
		check(t, err)
		ann = r.AnnouncementID
	}
	check(t, s.BGPAnnouncements().MarkAnnounced(ctx, ann, dao5bCurrentGen(t, s.BGPAnnouncements(), ann)))
	return s, ann, ids
}
func fuzhuoSet(t *testing.T, b Backend, id, n int, status string) {
	t.Helper()
	fixture, ok := b.(FuzhuoBackend)
	if !ok {
		t.Fatal("missing FuzhuoBackend fixture")
	}
	check(t, fixture.SetAnnouncement(id, n, status))
}
func runFuzhuoContract(t *testing.T, open func(*testing.T) Backend) {
	t.Run("Fuzhuo/C1_LiveIDs", func(t *testing.T) {
		b := open(t)
		s := b.Store()
		live := seedAttack(t, s, store.Attack{})
		ended := seedAttack(t, s, store.Attack{EndedAt: ptr(stamp(50))})
		got, err := s.Attacks().LiveIDs(ctx, []int{live, ended, 999999})
		check(t, err)
		equal(t, got, map[int]bool{live: true})
	})
	type scenario struct {
		name             string
		ref              int
		status           string
		ended            []bool
		detach           bool
		want             int
		wantStatus, skip string
		removed          []int
		withdraw         bool
	}
	cases := []scenario{
		{"normal", 1, "active", []bool{true}, true, 0, "withdrawing", "", []int{0}, true},
		{"shared", 2, "active", []bool{true, false}, true, 1, "active", "", []int{0}, false},
		{"phantom", 1, "active", []bool{true, false}, true, 1, "active", "", []int{0}, false},
		{"undercount_empty_D", 1, "active", []bool{false, false}, true, 2, "active", "", nil, false},
		{"overcount", 2, "active", []bool{true}, true, 2, "active", "refcount_exceeds_attachments", nil, false},
		{"consistent", 1, "active", []bool{false}, true, 1, "active", "consistent", nil, false},
		{"up_all_rows", 1, "active", []bool{true, false, false}, false, 3, "active", "", nil, false},
		{"up_announcing", 1, "announcing", []bool{false, false}, false, 2, "announcing", "", nil, false},
		{"up_no_downcount", 3, "active", []bool{true, false}, false, 3, "active", "consistent", nil, false},
	}
	for _, status := range []string{"delayed", "announcing", "withdrawing", "failed"} {
		cases = append(cases, scenario{name: "non_active_" + status, ref: 1, status: status, ended: []bool{true}, detach: true, want: 1, wantStatus: status, skip: "status=" + status})
	}
	for _, status := range []string{"delayed", "withdrawing", "failed"} {
		cases = append(cases, scenario{name: "up_non_active_" + status, ref: 1, status: status, ended: []bool{true, false}, want: 1, wantStatus: status, skip: "status=" + status})
	}
	for _, tc := range cases {
		t.Run("Fuzhuo/C2_"+tc.name, func(t *testing.T) {
			b := open(t)
			s, ann, ids := fuzhuoSeed(t, b, tc.ended...)
			fuzhuoSet(t, b, ann, tc.ref, tc.status)
			var ended []int
			for i, end := range tc.ended {
				if end {
					ended = append(ended, ids[i])
				}
			}
			before, err := s.BGPAnnouncements().ListEvents(ctx, ann)
			check(t, err)
			r, err := s.BGPAnnouncements().ReconcileAttachments(ctx, ann, ended, tc.detach)
			check(t, err)
			equal(t, r.RefcountBefore, tc.ref)
			equal(t, r.RefcountAfter, tc.want)
			equal(t, r.NeedWithdraw, tc.withdraw)
			equal(t, r.Skipped, tc.skip)
			wantRemoved := map[int]bool{}
			for _, i := range tc.removed {
				wantRemoved[ids[i]] = true
			}
			gotRemoved := map[int]bool{}
			for _, id := range r.Detached {
				gotRemoved[id] = true
			}
			equal(t, gotRemoved, wantRemoved)
			a, err := s.BGPAnnouncements().Get(ctx, ann)
			check(t, err)
			equal(t, a.Refcount, tc.want)
			equal(t, a.Status, tc.wantStatus)
			rows, err := s.BGPAnnouncements().ListAttacks(ctx, ann)
			check(t, err)
			for _, row := range rows {
				equal(t, row.DetachedAt != nil, wantRemoved[row.AttackID])
			}
			after, err := s.BGPAnnouncements().ListEvents(ctx, ann)
			check(t, err)
			changed := tc.skip == ""
			extra := 0
			if changed {
				extra = 1
			}
			equal(t, len(after)-len(before), extra)
			if changed {
				found := false
				for _, event := range after {
					if strings.Contains(event.Detail, "reconcile") {
						found = true
					}
				}
				equal(t, found, true)
			}
		})
	}
	for _, name := range []string{"R1_ended_and_live", "R2_detach_remaining", "R1b_current_is_residual", "R3_empty_residual"} {
		t.Run("Fuzhuo/C4_"+name, func(t *testing.T) {
			b := open(t)
			s, ann, ids := fuzhuoSeed(t, b, true, false)
			a, err := s.BGPAnnouncements().Get(ctx, ann)
			check(t, err)
			c := seedAttack(t, s, store.Attack{})
			want := 2
			if name == "R1b_current_is_residual" {
				c = ids[0]
				row, err := s.Attacks().Get(ctx, c)
				check(t, err)
				row.EndedAt = nil
				check(t, s.Attacks().Update(ctx, row))
				_, err = s.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{Prefix: a.Prefix, RouteMap: a.RouteMap, ConnectorID: a.ConnectorID, AttackID: ids[1], DelayMinutes: 5})
				check(t, err)
			}
			if name == "R3_empty_residual" {
				_, err := s.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{Prefix: a.Prefix, RouteMap: a.RouteMap, ConnectorID: a.ConnectorID, AttackID: ids[1], DelayMinutes: 5})
				check(t, err)
				_, _, err = s.BGPAnnouncements().ForceWithdraw(ctx, ann)
				check(t, err)
				check(t, s.BGPAnnouncements().MarkWithdrawn(ctx, ann, dao5bCurrentGen(t, s.BGPAnnouncements(), ann)))
				want = 1
			} else {
				fuzhuoSet(t, b, ann, 0, "failed")
			}
			r, err := s.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{Prefix: a.Prefix, RouteMap: a.RouteMap, ConnectorID: a.ConnectorID, AttackID: c})
			check(t, err)
			equal(t, r.NeedAnnounce, true)
			a, err = s.BGPAnnouncements().Get(ctx, ann)
			check(t, err)
			if name != "R2_detach_remaining" {
				equal(t, a.Refcount, want)
			}
			delay := 0
			if name == "R1b_current_is_residual" {
				delay = 5
			}
			equal(t, a.DelayMinutes, delay)
			rows, err := s.BGPAnnouncements().ListAttacks(ctx, ann)
			check(t, err)
			for _, row := range rows {
				if name == "R2_detach_remaining" {
					continue
				}
				detached := false
				if name == "R1_ended_and_live" {
					detached = row.AttackID == ids[0]
				}
				if name == "R3_empty_residual" {
					detached = row.AttackID != c
				}
				equal(t, row.DetachedAt != nil, detached)
			}
			if name != "R3_empty_residual" {
				check(t, s.BGPAnnouncements().MarkAnnounced(ctx, ann, dao5bCurrentGen(t, s.BGPAnnouncements(), ann)))
				d, err := s.BGPAnnouncements().Detach(ctx, c, a.Prefix, a.RouteMap, a.ConnectorID)
				check(t, err)
				equal(t, d.NeedWithdraw, false)
				equal(t, d.Delayed, false)
				a, err = s.BGPAnnouncements().Get(ctx, ann)
				check(t, err)
				equal(t, a.Refcount, 1)
			}
		})
	}
}
