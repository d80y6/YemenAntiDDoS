package postgres

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// DAO14D2_HEAD=1 selects only the two baseline-specific fixture checks in B/F.
// It never changes the behavioral expectations that must fail on the baseline.
type dao14d2Fixture struct {
	t   *testing.T
	db  *PGStore
	ctx context.Context
}

func dao14d2New(t *testing.T) *dao14d2Fixture {
	t.Helper()
	f := &dao14d2Fixture{t, newPostgresContractBackend(t).(*postgresContractBackend).db, context.Background()}
	f.dump()
	return f
}
func (f *dao14d2Fixture) check(err error) {
	f.t.Helper()
	if err != nil {
		f.t.Fatalf("fixture invalid: %v", err)
	}
}
func (f *dao14d2Fixture) exec(q string, args ...any) {
	f.t.Helper()
	_, err := f.db.pool.Exec(f.ctx, q, args...)
	f.check(err)
}
func (f *dao14d2Fixture) text(q string, args ...any) string {
	f.t.Helper()
	var s string
	f.check(f.db.pool.QueryRow(f.ctx, q, args...).Scan(&s))
	return s
}
func (f *dao14d2Fixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	f.check(f.db.pool.QueryRow(f.ctx, q, args...).Scan(&n))
	return n
}
func (f *dao14d2Fixture) want(name string, got, want any) {
	f.t.Helper()
	f.t.Logf("ASSERT %s got=%v want=%v", name, got, want)
	if !reflect.DeepEqual(got, want) {
		f.t.Errorf("%s: got=%v want=%v", name, got, want)
	}
}
func (f *dao14d2Fixture) require(name string, ok bool) {
	f.t.Helper()
	if !ok {
		f.t.Fatalf("fixture invalid: %s", name)
	}
	f.t.Logf("FIXTURE %s PASS", name)
}
func (f *dao14d2Fixture) run(name string, body func(*dao14d2Fixture)) {
	f.t.Run(name, func(t *testing.T) {
		sub := *f
		sub.t = t
		defer sub.dump()
		body(&sub)
	})
}
func dao14d2Capture(t *testing.T, body func()) string {
	t.Helper()
	var b bytes.Buffer
	prior := log.Writer()
	log.SetOutput(&b)
	defer log.SetOutput(prior)
	body()
	t.Logf("RAW log: %s", b.String())
	return b.String()
}
func (f *dao14d2Fixture) migrate(days int) string {
	ret := dao13dRetention()
	ret.TSStatsCaggDays = days
	return dao14d2Capture(f.t, func() { f.check(f.db.AutoMigrate(f.ctx, ret)) })
}
func (f *dao14d2Fixture) mat() string {
	return f.text(`SELECT format('%I.%I',materialization_hypertable_schema,materialization_hypertable_name) FROM timescaledb_information.continuous_aggregates WHERE view_schema=current_schema() AND view_name='ts_stats_5min'`)
}
func (f *dao14d2Fixture) width() string {
	return f.text(`SELECT time_interval::text FROM timescaledb_information.dimensions WHERE (hypertable_schema,hypertable_name) IN (SELECT materialization_hypertable_schema,materialization_hypertable_name FROM timescaledb_information.continuous_aggregates WHERE view_schema=current_schema() AND view_name='ts_stats_5min') AND column_name='bucket'`)
}
func (f *dao14d2Fixture) jobs(proc string) []dao13dJob {
	j := (&dao13dFixture{t: f.t, db: f.db, c: f.ctx}).jobs("ts_stats_5min", proc)
	f.require("one cagg "+proc+" job", len(j) == 1)
	return j
}
func (f *dao14d2Fixture) dump() {
	f.t.Helper()
	queries := []string{
		`SELECT extversion FROM pg_extension WHERE extname='timescaledb'`,
		`SELECT COALESCE(jsonb_agg(to_jsonb(c)), '[]')::text FROM timescaledb_information.continuous_aggregates c WHERE view_schema=current_schema() AND view_name='ts_stats_5min'`,
		`SELECT COALESCE(jsonb_agg(to_jsonb(d)), '[]')::text FROM timescaledb_information.dimensions d WHERE (hypertable_schema,hypertable_name) IN (SELECT materialization_hypertable_schema,materialization_hypertable_name FROM timescaledb_information.continuous_aggregates WHERE view_schema=current_schema() AND view_name='ts_stats_5min')`,
		`SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY range_start,chunk_name), '[]')::text FROM timescaledb_information.chunks c WHERE (hypertable_schema,hypertable_name) IN (SELECT materialization_hypertable_schema,materialization_hypertable_name FROM timescaledb_information.continuous_aggregates WHERE view_schema=current_schema() AND view_name='ts_stats_5min')`,
		`SELECT COALESCE(jsonb_agg(to_jsonb(j) ORDER BY job_id), '[]')::text FROM timescaledb_information.jobs j WHERE proc_name IN ('policy_refresh_continuous_aggregate','policy_retention','policy_compression')`,
	}
	for i, q := range queries {
		var raw string
		err := f.db.pool.QueryRow(f.ctx, q).Scan(&raw)
		f.t.Logf("RAW catalog[%d] %s err=%v", i, raw, err)
		if err != nil {
			f.t.Errorf("catalog evidence: %v", err)
		}
	}
}
func (f *dao14d2Fixture) pause() {
	f.exec(`SELECT alter_job(job_id,scheduled => false) FROM timescaledb_information.jobs WHERE proc_name IN ('policy_refresh_continuous_aggregate','policy_retention','policy_compression')`)
	f.require("all related jobs paused", f.count(`SELECT count(*) FROM timescaledb_information.jobs WHERE scheduled AND proc_name IN ('policy_refresh_continuous_aggregate','policy_retention','policy_compression')`) == 0)
	f.t.Logf("RAW job_stats: %s", f.text(`SELECT COALESCE(jsonb_agg(to_jsonb(s)), '[]')::text FROM timescaledb_information.job_stats s JOIN timescaledb_information.jobs j USING(job_id) WHERE j.proc_name IN ('policy_refresh_continuous_aggregate','policy_retention','policy_compression')`))
	f.require("no related background job running", f.count(`SELECT count(*) FROM timescaledb_information.job_stats s JOIN timescaledb_information.jobs j USING(job_id) WHERE j.proc_name IN ('policy_refresh_continuous_aggregate','policy_retention','policy_compression') AND lower(s.job_status)='running'`) == 0)
	f.dump()
}
func (f *dao14d2Fixture) seed(node string, at time.Time, pps int64) {
	f.exec(`INSERT INTO ts_stats(time,node_id,prefix,direction,dst_ip,pps,bps,extra_decoder_pps,extra_decoder_bps) VALUES($1,$2,'192.0.2.0/25','receives',NULL,$3,1000,'{"tcp_ack":10}','{"tcp_ack":1000}')`, at, node, pps)
}
func (f *dao14d2Fixture) refresh(from, to time.Time) {
	f.exec(`CALL refresh_continuous_aggregate('ts_stats_5min',$1::timestamptz,$2::timestamptz)`, from, to)
}
func (f *dao14d2Fixture) buckets(node string) int {
	return f.count("SELECT count(*) FROM ts_stats_5min WHERE node_id=$1", node)
}

func TestDao14d2_G23_A(t *testing.T) {
	f := dao14d2New(t)
	for i, step := range []struct {
		days  int
		width string
	}{{90, "12 days"}, {14, "2 days"}, {0, "2 days"}, {1, "1 day"}} {
		if i > 0 {
			f.migrate(step.days)
		}
		f.want(fmt.Sprintf("G23-A/cagg=%d", step.days), f.width(), step.width)
		f.dump()
	}
}
func TestDao14d2_G23_B(t *testing.T) {
	f := dao14d2New(t)
	f.migrate(1)
	f.pause()
	now := time.Now().UTC()
	old, recent := now.Add(-72*time.Hour), now.Add(-30*time.Minute)
	f.seed("dao14d2-old", old, 100)
	f.seed("dao14d2-recent", recent, 100)
	f.refresh(now.Add(-96*time.Hour), now)
	f.require("old and recent buckets present", f.buckets("dao14d2-old") == 1 && f.buckets("dao14d2-recent") == 1)
	var end time.Time
	f.check(f.db.pool.QueryRow(f.ctx, `SELECT range_end FROM timescaledb_information.chunks WHERE (hypertable_schema,hypertable_name) IN (SELECT materialization_hypertable_schema,materialization_hypertable_name FROM timescaledb_information.continuous_aggregates WHERE view_schema=current_schema() AND view_name='ts_stats_5min') AND range_start <= $1 AND range_end > $1`, old.Truncate(5*time.Minute)).Scan(&end))
	cutoff := now.Add(-24 * time.Hour)
	f.t.Logf("RAW old chunk range_end=%s retention cutoff=%s HEAD=%t", end, cutoff, os.Getenv("DAO14D2_HEAD") == "1")
	if os.Getenv("DAO14D2_HEAD") == "1" {
		f.require("HEAD old wide chunk has not expired", end.After(cutoff))
	} else {
		f.want("G23-B/old chunk expired", !end.After(cutoff), true)
	}
	f.exec(fmt.Sprintf("CALL run_job(%d)", f.jobs("policy_retention")[0].ID))
	f.want("G23-B/old removed", f.buckets("dao14d2-old"), 0)
	f.want("G23-B/recent retained", f.buckets("dao14d2-recent"), 1)
	f.dump()
}
func TestDao14d2_G23_C(t *testing.T) {
	f := dao14d2New(t)
	snapshot := func() string {
		return fmt.Sprint(f.width(), f.text(`SELECT 'ts_stats_5min'::regclass::oid::text`), f.jobs("policy_retention"), f.jobs("policy_refresh_continuous_aggregate"))
	}
	logs := []string{f.migrate(90)}
	before := snapshot()
	logs = append(logs, f.migrate(90))
	f.want("G23-C/width OID job_id config unchanged", snapshot(), before)
	f.run("LogOnce", func(f *dao14d2Fixture) {
		for i, raw := range logs {
			f.want(fmt.Sprintf("G23-C/LogOnce/start%d", i+1), strings.Count(raw, "chunk interval: ts_stats_5min ("), 1)
			f.want("G23-C/LogOnce/no warning", strings.Count(raw, "WARNING: chunk interval for ts_stats_5min"), 0)
		}
	})
}
func TestDao14d2_G23_D(t *testing.T) {
	f := dao14d2New(t)
	before := f.mat()
	f.exec("DROP MATERIALIZED VIEW ts_stats_5min CASCADE")
	f.migrate(90)
	f.want("G23-D/materialization changed", f.mat() != before, true)
	f.t.Logf("RAW materialization before=%s after=%s", before, f.mat())
	f.want("G23-D/rebuilt width", f.width(), "12 days")
	f.jobs("policy_retention")
	f.jobs("policy_refresh_continuous_aggregate")
	f.dump()
}
func TestDao14d2_G23_F(t *testing.T) {
	f := dao14d2New(t)
	f.pause()
	f.exec("SELECT set_chunk_time_interval($1::regclass,$2::interval)", f.mat(), "70 days")
	now := time.Now().UTC()
	f.seed("dao14d2-wide", now.Add(-2*time.Hour), 100)
	f.refresh(now.Add(-3*time.Hour), now)
	f.require("one historical bucket", f.buckets("dao14d2-wide") == 1)
	chunks := func() string {
		return f.text(`SELECT COALESCE(jsonb_agg(jsonb_build_array(chunk_schema,chunk_name,range_start,range_end) ORDER BY chunk_name),'[]')::text FROM timescaledb_information.chunks WHERE (hypertable_schema,hypertable_name) IN (SELECT materialization_hypertable_schema,materialization_hypertable_name FROM timescaledb_information.continuous_aggregates WHERE view_schema=current_schema() AND view_name='ts_stats_5min')`)
	}
	data := func() string {
		return f.text(`SELECT jsonb_agg(jsonb_build_array(bucket,avg_pps) ORDER BY bucket)::text FROM ts_stats_5min WHERE node_id='dao14d2-wide'`)
	}
	beforeChunks, beforeData := chunks(), data()
	f.t.Logf("RAW old chunks=%s data=%s", beforeChunks, beforeData)
	for i := 0; i < 2; i++ {
		f.migrate(90)
		f.want("G23-F/old chunk identity and span", chunks(), beforeChunks)
		f.want("G23-F/old cagg rows", data(), beforeData)
		if os.Getenv("DAO14D2_HEAD") != "1" {
			f.want("G23-F/future width", f.width(), "12 days")
		}
		f.dump()
	}
}

func dao14d2Points(f *dao14d2Fixture, name string, got []store.TimeseriesPoint, err error, base time.Time, resolution string, extras bool) {
	f.t.Helper()
	f.want(name+"/error", err, nil)
	n := 2
	if resolution == "1h" {
		n = 1
	}
	f.want(name+"/rows", len(got), n)
	for i, p := range got {
		want := store.TimeseriesPoint{Time: base.Add(time.Duration(i) * 5 * time.Minute), PPS: 100, BPS: 1000}
		if extras {
			want.ExtraDecoderPPS = map[string]int32{"tcp_ack": 10}
			want.ExtraDecoderBPS = map[string]int64{"tcp_ack": 1000}
		}
		f.want(name+"/timestamp", p.Time.Equal(want.Time), true)
		p.Time = want.Time
		f.want(name+"/all fields", p, want)
	}
}
func TestDao14d2_Q32(t *testing.T) {
	f := dao14d2New(t)
	f.pause()
	now := time.Now().UTC()
	base := now.Truncate(time.Hour).Add(-time.Hour)
	node := "dao14d2-q32"
	f.seed(node, base, 100)
	f.seed(node, base.Add(5*time.Minute), 100)
	f.refresh(base, base.Add(10*time.Minute))
	f.seed(node, base.Add(30*time.Minute), 10000)
	f.require("exactly two materialized buckets", f.buckets(node) == 2)
	f.require("materialized_only is true", f.text(`SELECT materialized_only::text FROM timescaledb_information.continuous_aggregates WHERE view_schema=current_schema() AND view_name='ts_stats_5min'`) == "true")
	r := f.db.stats
	filter := store.TimeseriesFilter{NodeID: node, From: now.Add(-2 * time.Hour), To: base.Add(time.Hour), Resolution: "5min"}
	f.run("Q32-A", func(f *dao14d2Fixture) {
		for _, res := range []string{"5min", "1h"} {
			for _, extra := range []bool{true, false} {
				f.run(fmt.Sprintf("%s/%t", res, extra), func(f *dao14d2Fixture) {
					q := filter
					q.From = base
					q.Resolution = res
					q.IncludeExtras = extra
					p, err := r.queryTimeseriesFromCagg(f.ctx, q, 100)
					f.want("Q32-A/error", err, nil)
					f.want("Q32-A/nonempty", len(p) >= 1, true)
				})
			}
		}
	})
	f.run("Q32-B", func(f *dao14d2Fixture) {
		p, err := r.queryTimeseriesFromRaw(f.ctx, filter, 100)
		f.require("raw signal query succeeds", err == nil)
		f.require("raw signal has three points including sentinel", len(p) == 3 && p[2].Time.Equal(base.Add(30*time.Minute)) && p[2].PPS == 10000)
		f.t.Logf("RAW distinguishability raw=%+v", p)
		q := filter
		q.IncludeExtras = true
		raw := dao14d2Capture(f.t, func() { p, err = r.QueryTimeseries(f.ctx, q) })
		f.require("cagg signal visible without warning", err == nil && len(p) == 2 && strings.Count(raw, "cagg query failed") == 0)
		f.t.Logf("RAW distinguishability cagg=%+v", p)
		for _, res := range []string{"5min", "1h"} {
			for _, total := range []bool{false, true} {
				f.run(fmt.Sprintf("%s/total=%t", res, total), func(f *dao14d2Fixture) {
					q := filter
					q.Resolution = res
					query := r.QueryTimeseries
					if total {
						q.NodeID = ""
						query = r.QueryTotalTimeseries
					}
					var p []store.TimeseriesPoint
					var err error
					raw := dao14d2Capture(f.t, func() { p, err = query(f.ctx, q) })
					f.want("Q32-B/no fallback", strings.Count(raw, "cagg query failed"), 0)
					dao14d2Points(f, "Q32-B", p, err, base, res, false)
					q.IncludeExtras = true
					with, err := query(f.ctx, q)
					f.want("Q32-B/extras error", err, nil)
					for i := range with {
						with[i].ExtraDecoderPPS = nil
						with[i].ExtraDecoderBPS = nil
					}
					f.want("Q32-B/12 fields equal extras path", p, with)
				})
			}
		}
	})
	f.run("Q32-C", func(f *dao14d2Fixture) {
		for _, res := range []string{"5min", "1h"} {
			f.run(res, func(f *dao14d2Fixture) {
				q := filter
				q.Resolution = res
				q.IncludeExtras = true
				p, err := r.queryTimeseriesFromCagg(f.ctx, q, 100)
				dao14d2Points(f, "Q32-C", p, err, base, res, true)
			})
		}
	})
	f.run("Q32-E", func(f *dao14d2Fixture) {
		oldNode := "dao14d2-q32old"
		before := f.count("SELECT count(*) FROM ts_stats WHERE node_id=$1", node)
		f.seed(oldNode, now.Add(-72*time.Hour), 700)
		f.refresh(now.Add(-96*time.Hour), now.Add(-48*time.Hour))
		f.require("old cagg seed materialized", f.buckets(oldNode) == 1)
		f.exec("SELECT drop_chunks('ts_stats',older_than => $1::timestamptz)", now.Add(-48*time.Hour))
		f.require("old raw gone and cagg retained", f.count("SELECT count(*) FROM ts_stats WHERE node_id=$1", oldNode) == 0 && f.buckets(oldNode) == 1)
		f.require("recent raw seed unaffected", f.count("SELECT count(*) FROM ts_stats WHERE node_id=$1", node) == before)
		q := filter
		q.NodeID = oldNode
		q.From = now.Add(-96 * time.Hour)
		var p []store.TimeseriesPoint
		var err error
		raw := dao14d2Capture(f.t, func() { p, err = r.QueryTimeseries(f.ctx, q) })
		f.want("Q32-E/error", err, nil)
		f.want("Q32-E/rows", len(p), 1)
		if len(p) == 1 {
			f.want("Q32-E/pps", p[0].PPS, int64(700))
		}
		f.want("Q32-E/no fallback", strings.Count(raw, "cagg query failed"), 0)
	})
	f.run("Q32-D", func(f *dao14d2Fixture) {
		f.exec("DROP MATERIALIZED VIEW ts_stats_5min CASCADE")
		var p []store.TimeseriesPoint
		var err error
		raw := dao14d2Capture(f.t, func() { p, err = r.QueryTimeseries(f.ctx, filter) })
		f.want("Q32-D/error", err, nil)
		f.want("Q32-D/fallback once", strings.Count(raw, "cagg query failed"), 1)
		f.want("Q32-D/rows", len(p), 3)
		if len(p) == 3 {
			f.want("Q32-D/sentinel", p[2].PPS, int64(10000))
		}
	})
}
