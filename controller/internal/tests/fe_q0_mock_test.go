package tests

import (
	"context"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// TestFEQ0_SharedMockFilter keeps the shared mock in step with buildAttackWhere (fe-q0 authorization #1).
func TestFEQ0_SharedMockFilter(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	before := t0.Add(-time.Hour)
	s := NewMockStore()
	for i, target := range []string{"198.51.100.7", "198.51.100.0/24", "203.0.113.9"} {
		a := &store.Attack{DstIP: target, StartedAt: before, Direction: "receives", DecoderFamily: "udp"}
		id, err := s.Attacks().Create(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			a.ID = id
			a.EndedAt = &before
			if err := s.Attacks().Update(ctx, a); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		name string
		f    store.AttackFilter
		want int
	}{
		{"positive-no-filter", store.AttackFilter{}, 3},
		{"host", store.AttackFilter{DstIP: "198.51.100.7"}, 1},
		{"network", store.AttackFilter{DstIP: "198.51.100.0/24"}, 2},
		{"ended-after", store.AttackFilter{EndedAfter: &t0}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := s.Attacks().List(ctx, tc.f)
			if err != nil {
				t.Fatal(err)
			}
			count, err := s.Attacks().Count(ctx, tc.f)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("list=%d count=%d want=%d", len(rows), count, tc.want)
			if len(rows) != tc.want || count != tc.want {
				t.Fail()
			}
		})
	}
}
