package postgres

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestFEQS_G2_RealDBAttackSort(t *testing.T) {
	db := q0PG(t) // No DSN: skip before any connection.
	ctx := context.Background()
	base := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	end := base.Add(time.Hour)
	var ids []int
	for i, fixture := range []struct {
		peak      int64
		minutes   int
		direction string
		expired   bool
	}{{90, 0, "receives", false}, {80, 3, "receives", false}, {80, 1, "receives", false},
		{80, 1, "receives", false}, {10, 5, "receives", false}, {95, 2, "sends", false}, {85, 4, "receives", true}} {
		a := &store.Attack{DstIP: fmt.Sprintf("192.0.2.%d", i+1), Direction: fixture.direction,
			DecoderFamily: "udp", AttackType: "udp_flood", Severity: "high", Confidence: 1,
			PeakPPS: fixture.peak, StartedAt: base.Add(time.Duration(fixture.minutes) * time.Minute),
			ReasonCodes: []string{}, NodeSources: []string{"qs"}}
		id, err := db.Attacks().Create(ctx, a)
		q0PGCheck(t, err)
		ids = append(ids, id)
		if fixture.expired {
			a.ID, a.EndedAt = id, &end
			q0PGCheck(t, db.Attacks().Update(ctx, a))
		}
	}
	if !reflect.DeepEqual(ids, []int{1, 2, 3, 4, 5, 6, 7}) {
		t.Fatalf("distinct fixture IDs=%v want=[1 2 3 4 5 6 7]", ids)
	}
	for _, tc := range []struct {
		name   string
		filter store.AttackFilter
		want   []int
		count  int
	}{
		{"peak", store.AttackFilter{Sort: "peak_pps"}, []int{6, 1, 7, 2, 4, 3, 5}, 7},
		{"default", store.AttackFilter{}, []int{5, 7, 2, 6, 4, 3, 1}, 7},
		{"started_at", store.AttackFilter{Sort: "started_at"}, []int{5, 7, 2, 6, 4, 3, 1}, 7},
		{"active-receives-page", store.AttackFilter{Sort: "peak_pps", Status: "active", Direction: "receives", Limit: 2, Offset: 1}, []int{2, 4}, 5},
		{"expired-receives", store.AttackFilter{Sort: "peak_pps", Status: "expired", Direction: "receives"}, []int{7}, 1},
		{"active-sends", store.AttackFilter{Sort: "peak_pps", Status: "active", Direction: "sends"}, []int{6}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := db.Attacks().List(ctx, tc.filter)
			q0PGCheck(t, err)
			var got []int
			for _, row := range rows {
				got = append(got, row.ID)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ordered IDs=%v want=%v", got, tc.want)
			}
			for _, sort := range []string{"", "started_at", "peak_pps"} {
				f := tc.filter
				f.Sort = sort
				count, err := db.Attacks().Count(ctx, f)
				q0PGCheck(t, err)
				if count != tc.count {
					t.Errorf("Count sort=%q got=%d want=%d", sort, count, tc.count)
				}
			}
		})
	}
}
