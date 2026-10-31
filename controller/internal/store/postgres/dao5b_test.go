package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store/storetest"
)

type dao5bPGBackend struct {
	*postgresContractBackend
	t *testing.T
}

type dao5bDDLTrace struct{ t *testing.T }
type dao5bDDLStart struct{}

func (tr dao5bDDLTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if data.SQL == "ALTER TABLE bgp_announcements ADD COLUMN IF NOT EXISTS gen INTEGER NOT NULL DEFAULT 0" {
		return context.WithValue(ctx, dao5bDDLStart{}, time.Now())
	}
	return ctx
}
func (tr dao5bDDLTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if start, ok := ctx.Value(dao5bDDLStart{}).(time.Time); ok {
		tr.t.Logf("G1 ADD gen elapsed=%s error=%v", time.Since(start), data.Err)
	}
}

func (b dao5bPGBackend) SetGeneration(id, gen int) error {
	_, err := b.db.Pool().Exec(context.Background(), "UPDATE bgp_announcements SET gen=$2 WHERE id=$1", id, gen)
	return err
}
func (b dao5bPGBackend) PrepareLegacy() (int, error) {
	c := context.Background()
	_, err := b.db.Pool().Exec(c, "ALTER TABLE bgp_announcements DROP COLUMN IF EXISTS gen")
	if err != nil {
		return 0, err
	}
	var id int
	err = b.db.Pool().QueryRow(c, "INSERT INTO bgp_announcements(prefix,route_map,connector_id,status,refcount) VALUES('192.0.2.99/32','RTBH',7,'active',0) RETURNING id").Scan(&id)
	return id, err
}
func (b dao5bPGBackend) HasGen() (bool, error) {
	var yes bool
	err := b.db.Pool().QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='bgp_announcements' AND column_name='gen')").Scan(&yes)
	return yes, err
}
func (b dao5bPGBackend) Migrate() error {
	c := context.Background()
	var version string
	if err := b.db.Pool().QueryRow(c, "SELECT version()").Scan(&version); err != nil {
		return err
	}
	start := time.Now()
	config := b.db.Pool().Config()
	config.ConnConfig.Tracer = dao5bDDLTrace{b.t}
	pool, err := pgxpool.NewWithConfig(c, config)
	if err != nil {
		return err
	}
	defer pool.Close()
	err = (&PGStore{pool: pool}).AutoMigrate(c, RetentionConfig{})
	b.t.Logf("PostgreSQL=%s AutoMigrate elapsed=%s", version, time.Since(start))
	return err
}
func dao5bOpenPG(t *testing.T) storetest.Dao5bBackend {
	return dao5bPGBackend{newPostgresContractBackend(t).(*postgresContractBackend), t}
}
func TestDao5b_G1_Postgres(t *testing.T) { storetest.RunDao5bG1(t, dao5bOpenPG(t).(dao5bPGBackend)) }
func TestDao5b_G2_Postgres(t *testing.T) { storetest.RunDao5bG2(t, dao5bOpenPG) }
func TestDao5b_G3_Postgres(t *testing.T) { storetest.RunDao5bG3(t, dao5bOpenPG) }
func TestDao5b_G4_Postgres(t *testing.T) { storetest.RunDao5bG4(t, dao5bOpenPG) }

func TestDao11j_C1_Postgres(t *testing.T) { storetest.RunDao11jC1(t, dao5bOpenPG) }
