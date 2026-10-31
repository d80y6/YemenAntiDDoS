package postgres

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func TestFEQB_W13_RealDBSameTimePagination(t *testing.T) {
	// q0PG uses the disposable database fixture and skips before connecting
	// when XSIGHT_TEST_ADMIN_DSN is absent.
	db := q0PG(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	var inserted []int
	unique := make(map[int]bool)
	for _, target := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"} {
		// Different targets prevent Create from merging the unfinished attacks.
		id := q0PGAttack(t, db, target, base, nil)
		inserted = append(inserted, id)
		unique[id] = true
	}
	if len(unique) != 5 {
		t.Fatalf("created distinct IDs=%d want=5: %v", len(unique), inserted)
	}
	// Each isolated database starts with an empty attacks table and a fresh sequence.
	if !reflect.DeepEqual(inserted, []int{1, 2, 3, 4, 5}) {
		t.Fatalf("inserted IDs=%v want=[1 2 3 4 5] in ascending order", inserted)
	}
	var joined []int
	for _, page := range []struct {
		offset int
		want   []int
	}{{0, []int{5, 4}}, {2, []int{3, 2}}, {4, []int{1}}} {
		rows, err := db.Attacks().List(ctx, store.AttackFilter{Limit: 2, Offset: page.offset})
		q0PGCheck(t, err)
		var ids []int
		for _, row := range rows {
			if !row.StartedAt.Equal(base) {
				t.Fatalf("id=%d started_at=%v want=%v", row.ID, row.StartedAt, base)
			}
			ids = append(ids, row.ID)
		}
		if !reflect.DeepEqual(ids, page.want) {
			t.Errorf("offset=%d IDs=%v want=%v", page.offset, ids, page.want)
		}
		joined = append(joined, ids...)
	}
	if !reflect.DeepEqual(joined, []int{5, 4, 3, 2, 1}) {
		t.Fatalf("concatenated IDs=%v want=[5 4 3 2 1] with no duplicates or omissions", joined)
	}

	later := q0PGAttack(t, db, "192.0.2.6", base.Add(time.Minute), nil)
	if later != 6 {
		t.Fatalf("later ID=%d want=6", later)
	}
	rows, err := db.Attacks().List(ctx, store.AttackFilter{Limit: 2})
	q0PGCheck(t, err)
	var ids []int
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	if !reflect.DeepEqual(ids, []int{6, 5}) {
		t.Fatalf("first page after later insert=%v want=[6 5]", ids)
	}
}
