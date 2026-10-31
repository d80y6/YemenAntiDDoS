package postgres

import (
	"context"
	"reflect"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func TestDao14a2_PG_G6b(t *testing.T) {
	for _, c := range []struct {
		name                   string
		current, applied, fail int64
		pending                bool
		status                 string
	}{
		{"Fails", 88, 87, 88, true, "failed"},
		{"StaleVersionIgnored", 89, 87, 88, true, "pending"},
		{"AppliedSameVersionUnchanged", 87, 87, 87, false, "synced"},
		{"SamePendingVersionUnchanged", 87, 87, 87, true, "pending"},
		{"RecoversOnNextVersion", 88, 87, 88, true, "failed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			db := dao14PG(t)
			ctx := context.Background()
			repo := db.Nodes()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(repo.Create(ctx, &store.Node{ID: "n", APIKey: "test-key", Enabled: true}))
			must(repo.UpdateDeliveryVersionCurrent(ctx, "n", c.current))
			must(repo.UpdateACK(ctx, "n", c.applied))
			if c.pending {
				must(repo.UpdateDeliveryVersionCurrent(ctx, "n", c.current))
			}
			before, err := repo.Get(ctx, "n")
			must(err)
			must(repo.MarkConfigFailed(ctx, "n", c.fail))
			after, err := repo.Get(ctx, "n")
			must(err)
			if after.ConfigStatus != c.status {
				t.Errorf("status=%s want %s", after.ConfigStatus, c.status)
			}
			if after.DeliveryVersionCurrent != before.DeliveryVersionCurrent || after.DeliveryVersionApplied != before.DeliveryVersionApplied || !reflect.DeepEqual(after.LastACKAt, before.LastACKAt) {
				t.Errorf("version or ACK columns changed: before=%+v after=%+v", before, after)
			}
			if c.name == "RecoversOnNextVersion" {
				must(repo.UpdateDeliveryVersionCurrent(ctx, "n", 89))
				n, err := repo.Get(ctx, "n")
				must(err)
				if n.ConfigStatus != "pending" {
					t.Errorf("next version status=%s", n.ConfigStatus)
				}
				must(repo.UpdateACK(ctx, "n", 89))
				n, err = repo.Get(ctx, "n")
				must(err)
				if n.ConfigStatus != "synced" || n.DeliveryVersionApplied != 89 {
					t.Errorf("recovery=%+v", n)
				}
			}
		})
	}
	t.Run("MissingNode", func(t *testing.T) {
		db := dao14PG(t)
		ctx := context.Background()
		if err := db.Nodes().MarkConfigFailed(ctx, "missing", 88); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := db.Pool().QueryRow(ctx, "SELECT count(*) FROM nodes WHERE id=$1", "missing").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("missing node rows=%d", n)
		}
	})
}
