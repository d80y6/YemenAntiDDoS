package storetest

import (
	"reflect"
	"sync"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// RunDao13cF5 exercises the same atomic claim contract on Mock and PostgreSQL.
func RunDao13cF5(t *testing.T, open func(*testing.T) Dao5bBackend) {
	cases := []struct {
		name, status string
		ref, gen     int
		live, claim  bool
	}{
		{"FailedZeroRefNoAttachment.Claims", "failed", 0, 7, false, true},
		{"FailedZeroRefLiveAttachment.NoClaim", "failed", 0, 7, true, false},
		{"FailedPositiveRefNoAttachment.NoClaim", "failed", 1, 7, false, false},
		{"FailedPositiveRefLiveAttachment.NoClaim", "failed", 2, 7, true, false},
		{"WrongGeneration.NoClaim", "failed", 0, 6, false, false},
	}
	for _, status := range []string{"announcing", "active", "delayed", "withdrawing", "withdrawn", "orphan", "dismissed", "dismissed_on_upgrade"} {
		cases = append(cases, struct {
			name, status string
			ref, gen     int
			live, claim  bool
		}{status + ".NoClaim", status, 0, 7, false, false})
	}
	for _, tc := range cases {
		t.Run("F5."+tc.name, func(t *testing.T) {
			b := open(t)
			r, id := dao5bSeed(t, b, "active", 2)
			if !tc.live {
				_, _, err := r.ForceWithdraw(ctx, id)
				check(t, err)
			}
			check(t, b.SetAnnouncement(id, tc.ref, tc.status))
			check(t, b.SetGeneration(id, 7))
			before, err := r.Get(ctx, id)
			check(t, err)
			attachments, err := r.ListAttacks(ctx, id)
			check(t, err)
			live := 0
			for _, a := range attachments {
				if a.DetachedAt == nil {
					live++
				}
			}
			equal(t, live > 0, tc.live)
			events, err := r.ListEvents(ctx, id)
			check(t, err)
			gen, ok, err := r.ClaimFailedWithdraw(ctx, id, tc.gen)
			check(t, err)
			if ok != tc.claim || (ok && gen != 8) || (!ok && gen != 0) {
				t.Errorf("ASSERT F5.%s FAIL claim=(%d,%v); want claim=%v", tc.name, gen, ok, tc.claim)
			} else {
				t.Logf("ASSERT F5.%s PASS claim=(%d,%v)", tc.name, gen, ok)
			}
			after, err := r.Get(ctx, id)
			check(t, err)
			if tc.claim {
				before.Status, before.Gen = "withdrawing", 8
			}
			if !reflect.DeepEqual(before, after) {
				t.Errorf("other row fields changed: before=%+v after=%+v", before, after)
			}
			later, err := r.ListAttacks(ctx, id)
			check(t, err)
			equal(t, later, attachments)
			laterEvents, err := r.ListEvents(ctx, id)
			check(t, err)
			if tc.claim {
				equal(t, len(laterEvents), len(events)+1)
				found := 0
				for _, event := range laterEvents {
					if event.EventType == "withdraw_retry_claimed" {
						found++
					}
				}
				equal(t, found, 1)
			} else {
				equal(t, laterEvents, events)
			}
		})
	}
	t.Run("F5.Concurrent.ExactlyOneClaim", func(t *testing.T) {
		b := open(t)
		r, id := dao5bSeed(t, b, "active", 2)
		_, _, err := r.ForceWithdraw(ctx, id)
		check(t, err)
		check(t, b.SetAnnouncement(id, 0, "failed"))
		check(t, b.SetGeneration(id, 7))
		start := make(chan struct{})
		type result struct {
			gen int
			ok  bool
			err error
		}
		results := make(chan result, 2)
		var ready sync.WaitGroup
		ready.Add(2)
		for i := 0; i < 2; i++ {
			go func() {
				ready.Done()
				<-start
				gen, ok, err := r.ClaimFailedWithdraw(ctx, id, 7)
				results <- result{gen, ok, err}
			}()
		}
		ready.Wait()
		close(start)
		claimed := 0
		for i := 0; i < 2; i++ {
			res := <-results
			check(t, res.err)
			if res.ok {
				claimed++
				equal(t, res.gen, 8)
			} else {
				equal(t, res.gen, 0)
			}
		}
		equal(t, claimed, 1)
		t.Log("ASSERT F5.Concurrent.ExactlyOneClaim PASS")
	})
	t.Run("F5.Missing.NoClaim", func(t *testing.T) {
		b := open(t)
		gen, ok, err := b.Store().BGPAnnouncements().ClaimFailedWithdraw(ctx, 999999, 7)
		check(t, err)
		equal(t, gen, 0)
		equal(t, ok, false)
	})
}

// RunDao13cK2 checks all states and connector scoping without requiring a FK.
func RunDao13cK2(t *testing.T, open func(*testing.T) Dao5bBackend) {
	for _, status := range []string{"announcing", "active", "delayed", "withdrawing", "failed", "orphan", "withdrawn", "dismissed", "dismissed_on_upgrade"} {
		t.Run("K2."+status, func(t *testing.T) {
			b := open(t)
			r, id := dao5bSeed(t, b, status, 2)
			a, err := r.Get(ctx, id)
			check(t, err)
			_, err = r.Attach(ctx, store.BGPAttachParams{Prefix: "192.0.2.200/32", RouteMap: "RTBH", ConnectorID: a.ConnectorID + 999, AttackID: 999})
			check(t, err)
			got, err := r.CountLiveByConnector(ctx, a.ConnectorID)
			check(t, err)
			want := 1
			if status == "withdrawn" || status == "dismissed" || status == "dismissed_on_upgrade" {
				want = 0
			}
			equal(t, got, want)
			missing, err := r.CountLiveByConnector(ctx, a.ConnectorID+1000)
			check(t, err)
			equal(t, missing, 0)
		})
	}
}
