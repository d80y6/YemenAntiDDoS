package retention

import (
	"testing"
	"time"
)

func dao13dCleaner(t *testing.T, mixed, bug bool) {
	d := newDao7DB(t)
	old := d.now.Add(-30 * 24 * time.Hour)
	if mixed {
		d.exec("CREATE TABLE ts_stats_plain (LIKE ts_stats INCLUDING ALL)")
		d.exec("DROP TABLE ts_stats CASCADE")
		d.exec("ALTER TABLE ts_stats_plain RENAME TO ts_stats")
		d.exec("INSERT INTO ts_stats(time,node_id) VALUES($1,'dao13d-old'),($2,'dao13d-now')", old, d.now)
		d.migrate()
	}
	var ts, flow bool
	err := d.db.Pool().QueryRow(d.ctx, "SELECT EXISTS(SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_schema=current_schema() AND hypertable_name='ts_stats'), EXISTS(SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_schema=current_schema() AND hypertable_name='flow_logs')").Scan(&ts, &flow)
	if err != nil {
		t.Fatal(err)
	}
	if ts == mixed || !flow || !d.db.HasTimescale() {
		t.Fatalf("fixture hypertables ts=%t flow=%t extension=%t", ts, flow, d.db.HasTimescale())
	}
	if d.db.IsHypertable("ts_stats") != ts || d.db.IsHypertable("flow_logs") != flow {
		t.Fatal("B1 per-table probe mismatch")
	}
	rows, err := d.db.Pool().Query(d.ctx, "SELECT job_id FROM timescaledb_information.jobs WHERE proc_name IN ('policy_retention','policy_compression')")
	if err != nil {
		t.Fatal(err)
	}
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	for _, id := range ids {
		d.exec("SELECT alter_job($1, scheduled => false)", id)
		var raw string
		if err := d.db.Pool().QueryRow(d.ctx, "SELECT to_jsonb(j)::text FROM timescaledb_information.jobs j WHERE job_id=$1 AND NOT scheduled", id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		t.Logf("RAW paused policy job: %s", raw)
	}
	if !mixed {
		d.exec("INSERT INTO ts_stats(time,node_id) VALUES($1,'dao13d-old'),($2,'dao13d-now')", old, d.now)
	}
	d.exec("INSERT INTO flow_logs(time,node_id,src_ip,dst_ip) VALUES($1,'dao13d-old','192.0.2.1','192.0.2.2')", old)
	dump := func() {
		for _, table := range []string{"ts_stats", "flow_logs", "timescaledb_information.jobs"} {
			var raw string
			if err := d.db.Pool().QueryRow(d.ctx, "SELECT COALESCE(jsonb_agg(to_jsonb(r)),'[]'::jsonb)::text FROM "+table+" r").Scan(&raw); err != nil {
				t.Fatal(err)
			}
			t.Logf("RAW %s: %s", table, raw)
		}
	}
	dump()
	New(d.db.Pool(), Config{TSStatsDays: 1, FlowLogsDays: 1, TSStatsHypertable: d.db.IsHypertable("ts_stats"), FlowLogsHypertable: d.db.IsHypertable("flow_logs")}).cleanup(d.ctx)
	dump()
	var oldTS, currentTS, oldFlow int
	if err := d.db.Pool().QueryRow(d.ctx, "SELECT count(*) FILTER(WHERE node_id='dao13d-old'),count(*) FILTER(WHERE node_id='dao13d-now') FROM ts_stats").Scan(&oldTS, &currentTS); err != nil {
		t.Fatal(err)
	}
	if err := d.db.Pool().QueryRow(d.ctx, "SELECT count(*) FROM flow_logs WHERE node_id='dao13d-old'").Scan(&oldFlow); err != nil {
		t.Fatal(err)
	}
	want := 1
	if mixed && !bug {
		want = 0
	}
	if oldTS != want || currentTS != 1 || oldFlow != 1 {
		t.Fatalf("ASSERT B1 retention ownership FAIL old_ts=%d want=%d current_ts=%d old_flow=%d", oldTS, want, currentTS, oldFlow)
	}
	t.Logf("ASSERT B1 retention ownership PASS old_ts=%d current_ts=%d old_flow=%d", oldTS, currentTS, oldFlow)
}
func TestDao13d_R0Fixed(t *testing.T) {
	t.Run("B1-A", func(t *testing.T) { dao13dCleaner(t, true, false) })
	t.Run("B1-B", func(t *testing.T) { dao13dCleaner(t, false, false) })
}
