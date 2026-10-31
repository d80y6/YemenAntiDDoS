package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/store/storetest"
)

func TestDao5_C2_PostgresContention(t *testing.T) {
	storetest.RunDao5CreateContention(t, func(t *testing.T) (store.AttackRepo, *pgxpool.Pool) {
		// Reuses the existing no-DSN skip and isolated database cleanup.
		b := newPostgresContractBackend(t).(*postgresContractBackend)
		cfg := b.db.Pool().Config()
		cfg.MaxConns, cfg.MinConns = 1, 0
		cfg.ConnConfig.RuntimeParams["application_name"] = "dao5-create"
		pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return &attackRepo{pool: pool}, pool
	})
}
