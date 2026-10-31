package postgres

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store/storetest"
	"testing"
)

func (b *postgresContractBackend) SetAnnouncement(id, refcount int, status string) error {
	_, err := b.db.Pool().Exec(context.Background(), `UPDATE bgp_announcements SET refcount=$2,status=$3 WHERE id=$1`, id, refcount, status)
	return err
}

func TestFuzhuo_Postgres(t *testing.T) {
	storetest.RunFuzhuoPostgres(t, func(t *testing.T) storetest.FuzhuoPostgres {
		b := newPostgresContractBackend(t).(*postgresContractBackend)
		cfg := b.db.Pool().Config()
		cfg.MaxConns, cfg.MinConns = 1, 0
		pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return storetest.FuzhuoPostgres{Backend: b, Pool: b.db.Pool(), TestRepo: &bgpAnnouncementRepo{pool: pool}, TestPool: pool, Migrate: func(ctx context.Context) error {
			return b.db.AutoMigrate(ctx, RetentionConfig{TSStatsDays: 7, TSStatsCompressDays: 1, TSStatsCaggDays: 90, FlowLogsDays: 7, FlowLogsCompressDays: 1})
		}}
	})
}
