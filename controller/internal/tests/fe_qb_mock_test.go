package tests

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestFEQB_W13b_MockSameTimePagination(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	ended := base.Add(2 * time.Hour)
	s := NewMockStore()
	// Equal timestamps span both storage groups. IDs also oppose time order,
	// so sorting by ID alone or sorting after pagination cannot satisfy the pages.
	s.attacks.appendAttacks(
		store.Attack{ID: 10, StartedAt: base},
		store.Attack{ID: 90, StartedAt: base.Add(-time.Hour)},
	)
	s.attacks.appendExpiredAttacks(
		store.Attack{ID: 30, StartedAt: base, EndedAt: &ended},
		store.Attack{ID: 20, StartedAt: base, EndedAt: &ended},
		store.Attack{ID: 5, StartedAt: base.Add(time.Hour), EndedAt: &ended},
	)
	var joined []int
	for _, page := range []struct {
		offset int
		want   []int
	}{{0, []int{5, 30}}, {2, []int{20, 10}}, {4, []int{90}}} {
		rows, err := s.Attacks().List(ctx, store.AttackFilter{Limit: 2, Offset: page.offset})
		if err != nil {
			t.Fatal(err)
		}
		var ids []int
		for _, row := range rows {
			ids = append(ids, row.ID)
		}
		if !reflect.DeepEqual(ids, page.want) {
			t.Errorf("offset=%d IDs=%v want=%v", page.offset, ids, page.want)
		}
		joined = append(joined, ids...)
	}
	if !reflect.DeepEqual(joined, []int{5, 30, 20, 10, 90}) {
		t.Fatalf("concatenated IDs=%v want=[5 30 20 10 90]", joined)
	}
}
