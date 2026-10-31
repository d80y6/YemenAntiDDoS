package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/store/storetest"
)

type postgresContractBackend struct{ db *PGStore }

func (b *postgresContractBackend) Store() store.Store { return b.db }
func (b *postgresContractBackend) SetTime(table, idColumn string, id int, column string, value time.Time) error {
	allowed := map[string]string{"action_execution_log": "executed_at", "action_manual_overrides": "created_at", "xdrop_active_rules": "created_at", "bgp_announcements": "announced_at", "bgp_announcement_attacks": "attached_at", "bgp_announcement_events": "created_at"}
	validKey := idColumn == "id" && table != "bgp_announcement_attacks"
	if table == "bgp_announcement_attacks" {
		validKey = idColumn == "attack_id" || idColumn == "announcement_id"
	}
	if allowed[table] != column || column == "" || !validKey {
		return fmt.Errorf("unsupported fixture target %s.%s/%s", table, column, idColumn)
	}
	q := "UPDATE " + pgx.Identifier{table}.Sanitize() + " SET " + pgx.Identifier{column}.Sanitize() + "=$1 WHERE " + pgx.Identifier{idColumn}.Sanitize() + "=$2"
	tag, err := b.db.Pool().Exec(context.Background(), q, value, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("fixture update affected %d rows; want 1", tag.RowsAffected())
	}
	return nil
}

func TestStoreContract_Postgres(t *testing.T) {
	if os.Getenv("XSIGHT_TEST_ADMIN_DSN") == "" {
		t.Skip("XSIGHT_TEST_ADMIN_DSN is not set")
	}
	storetest.RunContract(t, newPostgresContractBackend)
}

func newPostgresContractBackend(t *testing.T) storetest.Backend {
	dsn := os.Getenv("XSIGHT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("XSIGHT_TEST_ADMIN_DSN is not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	t.Cleanup(func() {
		if err := admin.Close(context.Background()); err != nil {
			t.Errorf("close admin: %v", err)
		}
	})
	return func() storetest.Backend {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			t.Fatal(err)
		}
		name := "xsight_ct_" + hex.EncodeToString(random[:])
		if !regexp.MustCompile(`^xsight_ct_[0-9a-f]{16}$`).MatchString(name) {
			t.Fatalf("unsafe database name %q", name)
		}
		quoted := pgx.Identifier{name}.Sanitize()
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
			t.Fatalf("create contract database: %v", err)
		}
		var db *PGStore
		// Register immediately after successful CREATE; New/migration/seed failures also clean up.
		t.Cleanup(func() {
			if db != nil {
				db.Close()
			}
			if _, err := admin.Exec(context.Background(), "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
				t.Errorf("drop %s: %v", name, err)
			}
		})
		targetDSN := dsn + " dbname=" + name
		if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatal(err)
			}
			u.Path = "/" + name
			q := u.Query()
			q.Set("dbname", name)
			u.RawQuery = q.Encode()
			targetDSN = u.String()
		}
		db, err = New(ctx, targetDSN)
		if err != nil {
			t.Fatalf("open contract database: %v", err)
		}
		var actual string
		if err := db.Pool().QueryRow(ctx, "SELECT current_database()").Scan(&actual); err != nil {
			t.Fatal(err)
		}
		if actual != name {
			t.Fatalf("refusing migration: current_database=%q, want %q", actual, name)
		}
		// Defaults from config.Load: retention 7/1/90 days, flow 7/1, automatic chunk sizes.
		if err := db.AutoMigrate(ctx, RetentionConfig{TSStatsDays: 7, TSStatsCompressDays: 1, TSStatsCaggDays: 90, FlowLogsDays: 7, FlowLogsCompressDays: 1}); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := db.Pool().QueryRow(ctx, `SELECT count(DISTINCT hypertable_name) FROM timescaledb_information.hypertables WHERE hypertable_schema='public' AND hypertable_name IN ('ts_stats','flow_logs')`).Scan(&count); err != nil {
			t.Fatalf("verify hypertables: %v", err)
		}
		if count != 2 {
			t.Fatalf("required hypertables found=%d; want ts_stats and flow_logs", count)
		}
		return &postgresContractBackend{db: db}
	}()
}
