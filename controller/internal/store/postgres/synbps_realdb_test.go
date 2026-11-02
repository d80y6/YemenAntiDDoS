package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/shared/decoder"
)

func synBPSFixture(t *testing.T) *dao14d2Fixture {
	t.Helper()
	return &dao14d2Fixture{t: t, db: newPostgresContractBackend(t).(*postgresContractBackend).db, ctx: context.Background()}
}

// All tests are serial: the catalog probe and the captured logger are process globals.
func synBPSQuery(t *testing.T, r *statsRepo, base time.Time, node, path string, extras bool) []store.TimeseriesPoint {
	t.Helper()
	parts := strings.Split(path, "_")
	filter := store.TimeseriesFilter{NodeID: node, From: base, To: base.Add(time.Hour), Resolution: parts[1], IncludeExtras: extras}
	var points []store.TimeseriesPoint
	var err error
	if parts[0] == "cagg" {
		if time.Since(filter.From) <= 90*time.Minute {
			t.Fatal("cagg fixture must route through the public QueryTimeseries cagg branch")
		}
		raw := dao14d2Capture(t, func() { points, err = r.QueryTimeseries(context.Background(), filter) })
		if n := strings.Count(raw, "cagg query failed"); n != 0 {
			t.Errorf("cagg fallback count=%d, want 0", n)
		}
	} else if path == "raw_5s" {
		points, err = r.QueryTimeseries(context.Background(), filter)
	} else {
		// Force the raw fallback SQL while keeping the same historical seed window.
		points, err = r.queryTimeseriesFromRaw(context.Background(), filter, 100)
	}
	if err != nil {
		t.Fatalf("%s extras=%t: %v", path, extras, err)
	}
	if len(points) == 0 {
		t.Fatalf("%s extras=%t returned no seeded buckets", path, extras)
	}
	return points
}

func TestSynBPS_G4_Values(t *testing.T) {
	f := synBPSFixture(t)
	r := &statsRepo{pool: f.db.pool}
	base := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	// Prefix A has two samples in bucket 0, B only one. Bucket 1 has A only.
	// Values are literal and pairwise different within every row: TCP/SYN/UDP/ICMP/frag.
	seeds := []struct {
		seconds int
		prefix  string
		bps     [5]int64
	}{
		{0, "192.0.2.0/25", [5]int64{200, 400, 600, 800, 1000}},
		{0, "192.0.2.128/25", [5]int64{800, 1600, 2400, 3200, 4000}},
		{5, "192.0.2.0/25", [5]int64{600, 1200, 1800, 2400, 3000}},
		{300, "192.0.2.0/25", [5]int64{1000, 2000, 3000, 4000, 5000}},
	}
	var input []store.StatPoint
	for _, seed := range seeds {
		seen := map[int64]bool{}
		for _, value := range seed.bps {
			if seen[value] {
				t.Fatal("seed BPS columns must be pairwise different")
			}
			seen[value] = true
		}
		prefix := seed.prefix
		p := store.StatPoint{Time: base.Add(time.Duration(seed.seconds) * time.Second), NodeID: "synbps-g4", Prefix: &prefix, Direction: "receives", PPS: 10, BPS: 10000}
		p.DecoderBPS[decoder.TCP], p.DecoderBPS[decoder.TCPSyn], p.DecoderBPS[decoder.UDP], p.DecoderBPS[decoder.ICMP], p.DecoderBPS[decoder.Frag] = seed.bps[0], seed.bps[1], seed.bps[2], seed.bps[3], seed.bps[4]
		p.DecoderPPS[decoder.TCPAck], p.DecoderBPS[decoder.TCPAck] = 3, 30
		input = append(input, p)
	}
	// Exercise the production COPY column/value binding, not a fixture INSERT.
	f.check(r.BulkInsert(f.ctx, input))
	f.exec(`CALL refresh_continuous_aggregate('ts_stats_5min',$1::timestamptz,$2::timestamptz)`, base, base.Add(time.Hour))
	// Hand arithmetic, frozen literals: cagg first bucket TCP=(200+600)/2+800=1200,
	// second=1000, hour=(1200+1000)/2=1100. Raw first bucket=(1000+600)/2=800,
	// hour=(1000+600+1000)/3=866 2/3 -> 867. Other columns use their own literal results.
	for _, tc := range []struct {
		path string
		want [][5]int64
	}{
		{"cagg_5min", [][5]int64{{1200, 2400, 3600, 4800, 6000}, {1000, 2000, 3000, 4000, 5000}}},
		{"cagg_1h", [][5]int64{{1100, 2200, 3300, 4400, 5500}}},
		{"raw_5s", [][5]int64{{1000, 2000, 3000, 4000, 5000}, {600, 1200, 1800, 2400, 3000}, {1000, 2000, 3000, 4000, 5000}}},
		{"raw_5min", [][5]int64{{800, 1600, 2400, 3200, 4000}, {1000, 2000, 3000, 4000, 5000}}},
		{"raw_1h", [][5]int64{{867, 1733, 2600, 3467, 4333}}},
	} {
		for _, extras := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/extras_%t", tc.path, extras), func(t *testing.T) {
				points := synBPSQuery(t, r, base, "synbps-g4", tc.path, extras)
				if len(points) != len(tc.want) {
					t.Fatalf("buckets=%d want=%d", len(points), len(tc.want))
				}
				for i, p := range points {
					got := [5]int64{p.TCPBPS, p.TCPSynBPS, p.UDPBPS, p.ICMPBPS, p.FragBPS}
					for j, name := range []string{"tcp_bps", "tcp_syn_bps", "udp_bps", "icmp_bps", "frag_bps"} {
						if got[j] != tc.want[i][j] {
							t.Errorf("bucket=%d %s=%d want=%d", i, name, got[j], tc.want[i][j])
						}
					}
				}
			})
		}
	}
}

// Steps 1-3 are shared by G5/G5b. Fresh AutoMigrate is performed by the fixture,
// then remove v8 before its referenced raw column, and restore frozen v7 SQL.
func synBPSOldV7(f *dao14d2Fixture) {
	f.t.Helper()
	f.exec(`DROP MATERIALIZED VIEW ts_stats_5min CASCADE`)
	f.exec(`ALTER TABLE ts_stats DROP COLUMN tcp_syn_bps`)
	f.exec(synBPSFrozenV7)
	f.require("v7 missing avg_tcp_syn_bps", f.count(`SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='ts_stats_5min' AND column_name='avg_tcp_syn_bps'`) == 0)
	f.require("v7 COALESCE marker", f.count(`SELECT count(*) FROM timescaledb_information.continuous_aggregates WHERE view_name='ts_stats_5min' AND view_definition LIKE '%COALESCE%'`) == 1)
}

func synBPSOID(f *dao14d2Fixture) string {
	return f.text(`SELECT oid::text FROM pg_class WHERE oid='ts_stats_5min'::regclass`)
}

func TestSynBPS_G5_Upgrade(t *testing.T) {
	f := synBPSFixture(t)
	synBPSOldV7(f)
	base := time.Now().UTC().Truncate(time.Hour).Add(-48 * time.Hour)
	// Step 4: insert an old row into a complete bucket inside the seven-day backfill.
	f.exec(`INSERT INTO ts_stats(time,node_id,prefix,direction,pps,bps) VALUES($1,'synbps-g5','192.0.2.0/24','receives',10,1000)`, base)
	// Step 5: compress the actual old row's chunk, then prove it is nonempty/compressed.
	chunk := f.text(`SELECT tableoid::regclass::text FROM ts_stats WHERE node_id='synbps-g5' AND time=$1`, base)
	f.exec(`SELECT compress_chunk($1::regclass)`, chunk)
	compressedOldRows := f.count(`SELECT count(*) FROM ts_stats s JOIN timescaledb_information.chunks c ON s.tableoid=format('%I.%I',c.chunk_schema,c.chunk_name)::regclass WHERE s.node_id='synbps-g5' AND s.time=$1 AND c.hypertable_name='ts_stats' AND c.is_compressed`, base)
	f.require("nonempty compressed old-row chunk", compressedOldRows >= 1)
	before := synBPSOID(f)
	t.Run("alter_compressed", func(t *testing.T) {
		if _, err := f.db.pool.Exec(f.ctx, synBPSMigration(t)); err != nil {
			t.Fatalf("ALTER on compressed hypertable: %v", err)
		}
	})
	if t.Failed() {
		return
	}
	t.Run("rebuild", func(t *testing.T) {
		raw := dao14d2Capture(t, func() { f.db.ensureCagg(f.ctx) })
		if synBPSOID(f) == before {
			t.Error("v7 cagg oid unchanged; expected v8 rebuild")
		}
		dao10RequireColumns(t, f.db, []string{"avg_tcp_syn_bps"})
		if !strings.Contains(raw, "from v7 to v8 (adding avg_tcp_syn_bps)") {
			t.Error("missing v7 -> v8 log based on original COALESCE marker")
		}
	})
	t.Run("old_row_nonnull_zero", func(t *testing.T) {
		var value pgtype.Int8
		if err := f.db.pool.QueryRow(f.ctx, `SELECT tcp_syn_bps FROM ts_stats WHERE node_id='synbps-g5' AND time=$1`, base).Scan(&value); err != nil {
			t.Fatal(err)
		}
		if !value.Valid || value.Int64 != 0 {
			t.Fatalf("old compressed row tcp_syn_bps=%+v; want non-NULL 0", value)
		}
	})
	for _, path := range []string{"cagg_5min", "cagg_1h", "raw_5s", "raw_5min", "raw_1h"} {
		for _, extras := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/extras_%t", path, extras), func(t *testing.T) {
				points := synBPSQuery(t, &statsRepo{pool: f.db.pool}, base, "synbps-g5", path, extras)
				if len(points) != 1 {
					t.Fatalf("old buckets=%d, want 1", len(points))
				}
				if !points[0].Time.Equal(base) || points[0].TCPSynBPS != 0 {
					t.Fatalf("old bucket time=%v SYN=%d, want %v / 0", points[0].Time, points[0].TCPSynBPS, base)
				}
			})
		}
	}
	t.Run("stable_twice", func(t *testing.T) {
		before := synBPSOID(f)
		for i := 0; i < 2; i++ {
			f.db.ensureCagg(f.ctx)
			if after := synBPSOID(f); after != before {
				t.Fatalf("call=%d oid changed %s -> %s", i+1, before, after)
			}
		}
	})
}

func TestSynBPS_G5b_CatalogFailure(t *testing.T) {
	f := synBPSFixture(t)
	synBPSOldV7(f)
	// Restore only the new raw column, without invoking AutoMigrate/ensureCagg.
	f.exec(synBPSMigration(t))
	f.require("old v7 still missing avg_tcp_syn_bps before injection", f.count(`SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='ts_stats_5min' AND column_name='avg_tcp_syn_bps'`) == 0)
	before := synBPSOID(f)
	original := probeCaggCOALESCE
	calls := 0
	probeCaggCOALESCE = func(context.Context, *pgxpool.Pool) (bool, error) {
		calls++
		return false, errors.New("synbps injected catalog failure")
	}
	t.Cleanup(func() { probeCaggCOALESCE = original })
	t.Run("missing_column_rebuilds", func(t *testing.T) {
		raw := dao14d2Capture(t, func() { f.db.ensureCagg(f.ctx) })
		if calls != 1 {
			t.Fatalf("probe calls=%d want=1", calls)
		}
		if !strings.Contains(raw, "WARNING: cagg check failed: synbps injected catalog failure") {
			t.Error("missing catalog failure warning")
		}
		if synBPSOID(f) == before {
			t.Error("catalog failure + missing column did not rebuild v7")
		}
		dao10RequireColumns(t, f.db, []string{"avg_tcp_syn_bps"})
	})
	t.Run("complete_columns_stable", func(t *testing.T) {
		dao10RequireColumns(t, f.db, []string{"avg_tcp_syn_bps"})
		before := synBPSOID(f)
		f.db.ensureCagg(f.ctx)
		if calls != 2 {
			t.Fatalf("probe calls=%d want=2", calls)
		}
		if after := synBPSOID(f); after != before {
			t.Fatalf("complete columns with unreadable catalog changed oid %s -> %s", before, after)
		}
	})
}

// Frozen 47e71ee v7 CREATE SQL, including its registry-expanded literal extras.
// Never derive this old schema from the current cagg builder.
const synBPSFrozenV7 = `
		CREATE MATERIALIZED VIEW ts_stats_5min
		WITH (timescaledb.continuous) AS
		SELECT time_bucket('5 minutes', time) AS bucket,
			   node_id, prefix, direction,
			   avg(pps)::BIGINT AS avg_pps,
			   avg(bps)::BIGINT AS avg_bps,
			   avg(tcp_pps)::INT AS avg_tcp_pps,
			   avg(tcp_syn_pps)::INT AS avg_tcp_syn_pps,
			   avg(udp_pps)::INT AS avg_udp_pps,
			   avg(icmp_pps)::INT AS avg_icmp_pps,
			   avg(frag_pps)::INT AS avg_frag_pps,
			   avg(tcp_bps)::BIGINT AS avg_tcp_bps,
			   avg(udp_bps)::BIGINT AS avg_udp_bps,
			   avg(icmp_bps)::BIGINT AS avg_icmp_bps,
			   avg(frag_bps)::BIGINT AS avg_frag_bps,
			   avg(COALESCE((extra_decoder_pps->>'tcp_ack')::int, 0))::INT AS avg_tcp_ack_pps, avg(COALESCE((extra_decoder_pps->>'tcp_rst')::int, 0))::INT AS avg_tcp_rst_pps, avg(COALESCE((extra_decoder_pps->>'tcp_fin')::int, 0))::INT AS avg_tcp_fin_pps, avg(COALESCE((extra_decoder_pps->>'gre')::int, 0))::INT AS avg_gre_pps, avg(COALESCE((extra_decoder_pps->>'esp')::int, 0))::INT AS avg_esp_pps, avg(COALESCE((extra_decoder_pps->>'igmp')::int, 0))::INT AS avg_igmp_pps, avg(COALESCE((extra_decoder_pps->>'ip_other')::int, 0))::INT AS avg_ip_other_pps, avg(COALESCE((extra_decoder_pps->>'bad_fragment')::int, 0))::INT AS avg_bad_fragment_pps, avg(COALESCE((extra_decoder_pps->>'invalid')::int, 0))::INT AS avg_invalid_pps,
			   avg(COALESCE((extra_decoder_bps->>'tcp_ack')::bigint, 0))::BIGINT AS avg_tcp_ack_bps, avg(COALESCE((extra_decoder_bps->>'tcp_rst')::bigint, 0))::BIGINT AS avg_tcp_rst_bps, avg(COALESCE((extra_decoder_bps->>'tcp_fin')::bigint, 0))::BIGINT AS avg_tcp_fin_bps, avg(COALESCE((extra_decoder_bps->>'gre')::bigint, 0))::BIGINT AS avg_gre_bps, avg(COALESCE((extra_decoder_bps->>'esp')::bigint, 0))::BIGINT AS avg_esp_bps, avg(COALESCE((extra_decoder_bps->>'igmp')::bigint, 0))::BIGINT AS avg_igmp_bps, avg(COALESCE((extra_decoder_bps->>'ip_other')::bigint, 0))::BIGINT AS avg_ip_other_bps, avg(COALESCE((extra_decoder_bps->>'bad_fragment')::bigint, 0))::BIGINT AS avg_bad_fragment_bps, avg(COALESCE((extra_decoder_bps->>'invalid')::bigint, 0))::BIGINT AS avg_invalid_bps
		FROM ts_stats
		WHERE dst_ip IS NULL
		GROUP BY bucket, node_id, prefix, direction
		WITH NO DATA
	`
