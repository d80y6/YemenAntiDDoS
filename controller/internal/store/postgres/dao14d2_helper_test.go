package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func dao14d2NoPanic(t *testing.T, body func()) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("helper panicked: %v", p)
		}
	}()
	body()
}
func dao14d2Warning(t *testing.T, raw string, parts ...string) {
	t.Helper()
	if strings.Count(raw, "\n") != 1 || strings.Contains(raw, "applies to new chunks") {
		t.Errorf("want one warning and no success: %q", raw)
	}
	for _, part := range append([]string{"WARNING", "ts_stats_5min"}, parts...) {
		if !strings.Contains(raw, part) {
			t.Errorf("warning missing %q: %q", part, raw)
		}
	}
}
func TestDao14d2_H1(t *testing.T) {
	raw := dao14d2Capture(t, func() {
		dao14d2NoPanic(t, func() { new(PGStore).applyCaggChunkInterval(context.Background(), "ts_stats_5min", 12) })
	})
	if raw != "" {
		t.Errorf("H1 want zero log bytes: %q", raw)
	}
}
func TestDao14d2_H2(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://u@192.0.2.1:5432/x")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	raw := dao14d2Capture(t, func() {
		dao14d2NoPanic(t, func() { (&PGStore{pool: pool, hasTimescale: true}).applyCaggChunkInterval(ctx, "ts_stats_5min", 12) })
	})
	dao14d2Warning(t, raw, "context canceled")
}
func TestDao14d2_G23_E(t *testing.T) {
	f := dao14d2New(t)
	f.run("E1", func(f *dao14d2Fixture) {
		f.exec("DROP MATERIALIZED VIEW ts_stats_5min CASCADE")
		raw := dao14d2Capture(f.t, func() { dao14d2NoPanic(f.t, func() { f.db.applyCaggChunkInterval(f.ctx, "ts_stats_5min", 12) }) })
		dao14d2Warning(f.t, raw, "not found")
	})
	f.migrate(90)
	f.run("E2", func(f *dao14d2Fixture) {
		mat, before := f.mat(), f.width()
		refresh, retention := f.jobs("policy_refresh_continuous_aggregate"), f.jobs("policy_retention")
		// Only the contract fixture's random database is changed. Its registered
		// Cleanup drops the database (and this setting), including on fatal errors.
		name := pgx.Identifier{f.text("SELECT current_database()")}.Sanitize()
		f.exec("ALTER DATABASE " + name + " SET default_transaction_read_only = on")
		// A new pool ensures new sessions inherit the database's read-only default.
		pool, err := pgxpool.NewWithConfig(f.ctx, f.db.pool.Config())
		f.check(err)
		defer pool.Close()
		ro := &dao14d2Fixture{f.t, &PGStore{pool: pool, hasTimescale: true}, f.ctx}
		ro.require("new session inherits read-only mode", ro.text("SHOW transaction_read_only") == "on")
		ro.require("read-only materialization lookup", ro.mat() == mat)
		_, seedErr := pool.Exec(f.ctx, "SELECT set_chunk_time_interval($1::regclass,$2::interval)", mat, "12 days")
		f.t.Logf("RAW read-only set error: %v", seedErr)
		f.require("read-only set error seed", seedErr != nil && strings.Contains(seedErr.Error(), "cannot execute set_chunk_time_interval() in a read-only transaction"))
		f.want("G23-E2/probe leaves width unchanged", ro.width(), before)
		raw := dao14d2Capture(f.t, func() { dao14d2NoPanic(f.t, func() { ro.db.applyCaggChunkInterval(f.ctx, "ts_stats_5min", 12) }) })
		dao14d2Warning(f.t, raw, mat, seedErr.Error())
		f.want("G23-E2/helper leaves width unchanged", ro.width(), before)
		// Continue with AutoMigrate's next two policy steps on the same pool.
		raw = dao14d2Capture(f.t, func() {
			ro.db.applyCaggRefreshPolicy(f.ctx, "ts_stats_5min", "12 hours", "1 minute", "5 minutes")
			ro.db.applyRetentionPolicy(f.ctx, "ts_stats_5min", 90)
		})
		f.want("G23-E2/policy warnings", strings.Count(raw, "WARNING"), 0)
		f.want("G23-E2/policy steps continue", strings.Count(raw, "unchanged, schedule preserved"), 2)
		f.want("G23-E2/refresh preserved", ro.jobs("policy_refresh_continuous_aggregate"), refresh)
		f.want("G23-E2/retention preserved", ro.jobs("policy_retention"), retention)
	})
}
