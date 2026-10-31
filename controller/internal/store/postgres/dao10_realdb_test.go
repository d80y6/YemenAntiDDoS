package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

func TestDao10_RealDB(t *testing.T) {
	// Reuse the dao2yi database lifecycle and its sole no-DSN skip condition.
	db := newPostgresContractBackend(t).(*postgresContractBackend).db
	ctx := context.Background()
	r := &statsRepo{pool: db.pool}
	base := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	t.Run("D1_Fresh", func(t *testing.T) {
		dao10RequireColumns(t, db, caggExtraColumnNames(extraDecoderNames()))
		for _, resolution := range []string{"5min", "1h"} {
			if _, err := r.queryTimeseriesFromCagg(ctx, store.TimeseriesFilter{Resolution: resolution, IncludeExtras: true}, 100); err != nil {
				t.Errorf("direct cagg %s: %v", resolution, err)
			}
		}
	})
	t.Run("D3_NoRedundantRebuild", func(t *testing.T) {
		oid := func() uint32 {
			var value uint32
			if err := db.pool.QueryRow(ctx, `SELECT oid FROM pg_class WHERE oid='ts_stats_5min'::regclass`).Scan(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		before := oid()
		for i := 0; i < 2; i++ {
			db.ensureCagg(ctx)
			if after := oid(); after != before {
				t.Errorf("ensureCagg call %d changed oid %d -> %d", i+1, before, after)
			}
		}
	})
	t.Run("D4_ExistingDataSemantics", func(t *testing.T) {
		// First bucket: prefix A has two times, B only one. Cagg averages
		// per prefix first; raw sums per timestamp first. Keep both behaviors.
		dao10InsertRows(t, db, base, "dao10-d4", []string{
			`{"tcp_ack":2,"gre":4,"invalid":6}`, `{"tcp_ack":8,"gre":12,"invalid":16}`,
			`{"tcp_ack":6,"invalid":10}`, `{"tcp_ack":10,"gre":20,"invalid":30}`,
		}, []string{
			`{"tcp_ack":200,"gre":400,"invalid":600}`, `{"tcp_ack":800,"gre":1200,"invalid":1600}`,
			`{"tcp_ack":600,"invalid":1000}`, `{"tcp_ack":1000,"gre":2000,"invalid":3000}`,
		})
		for _, tc := range []struct {
			path     string
			pps, bps []string
		}{
			{"cagg_5min", []string{`{"tcp_ack":12,"gre":14,"invalid":24}`, `{"tcp_ack":10,"gre":20,"invalid":30}`}, []string{`{"tcp_ack":1200,"gre":1400,"invalid":2400}`, `{"tcp_ack":1000,"gre":2000,"invalid":3000}`}},
			{"cagg_1h", []string{`{"tcp_ack":11,"gre":17,"invalid":27}`}, []string{`{"tcp_ack":1100,"gre":1700,"invalid":2700}`}},
			{"raw_5s", []string{`{"tcp_ack":10,"gre":16,"invalid":22}`, `{"tcp_ack":6,"invalid":10}`, `{"tcp_ack":10,"gre":20,"invalid":30}`}, []string{`{"tcp_ack":1000,"gre":1600,"invalid":2200}`, `{"tcp_ack":600,"invalid":1000}`, `{"tcp_ack":1000,"gre":2000,"invalid":3000}`}},
			{"raw_5min", []string{`{"tcp_ack":8,"gre":8,"invalid":16}`, `{"tcp_ack":10,"gre":20,"invalid":30}`}, []string{`{"tcp_ack":800,"gre":800,"invalid":1600}`, `{"tcp_ack":1000,"gre":2000,"invalid":3000}`}},
			{"raw_1h", []string{`{"tcp_ack":9,"gre":12,"invalid":21}`}, []string{`{"tcp_ack":867,"gre":1200,"invalid":2067}`}},
		} {
			t.Run(tc.path, func(t *testing.T) {
				points := dao10QueryPath(t, r, base, "dao10-d4", tc.path)
				dao10AssertExtras(t, points, tc.pps, tc.bps)
			})
		}
	})
	// The parent owns this mutation and cleanup. D5 must still see the new
	// name after D2's subtest finishes. No tests in this file run in parallel.
	previous := decoder.Names[14]
	decoder.Names[14] = "zz_dao10"
	t.Cleanup(func() { decoder.Names[14] = previous })
	t.Run("D2_AddedDecoderRebuilds", func(t *testing.T) {
		db.ensureCagg(ctx)
		dao10RequireColumns(t, db, []string{"avg_zz_dao10_pps", "avg_zz_dao10_bps"})
	})
	t.Run("D5_AllPathsIncludeAddedDecoder", func(t *testing.T) {
		dao10InsertRows(t, db, base, "dao10-d5", []string{
			`{"zz_dao10":2}`, `{"zz_dao10":8}`, `{"zz_dao10":6}`, `{"zz_dao10":10}`,
		}, []string{
			`{"zz_dao10":200}`, `{"zz_dao10":800}`, `{"zz_dao10":600}`, `{"zz_dao10":1000}`,
		})
		// Frozen arithmetic by path: cagg sums per-prefix averages; raw sums
		// per time then averages. Numeric -> integer casts round at the end.
		for _, tc := range []struct {
			path     string
			pps, bps []string
		}{
			{"cagg_5min", []string{`{"zz_dao10":12}`, `{"zz_dao10":10}`}, []string{`{"zz_dao10":1200}`, `{"zz_dao10":1000}`}},
			{"cagg_1h", []string{`{"zz_dao10":11}`}, []string{`{"zz_dao10":1100}`}},
			{"raw_5s", []string{`{"zz_dao10":10}`, `{"zz_dao10":6}`, `{"zz_dao10":10}`}, []string{`{"zz_dao10":1000}`, `{"zz_dao10":600}`, `{"zz_dao10":1000}`}},
			{"raw_5min", []string{`{"zz_dao10":8}`, `{"zz_dao10":10}`}, []string{`{"zz_dao10":800}`, `{"zz_dao10":1000}`}},
			{"raw_1h", []string{`{"zz_dao10":9}`}, []string{`{"zz_dao10":867}`}},
		} {
			t.Run(tc.path, func(t *testing.T) {
				points := dao10QueryPath(t, r, base, "dao10-d5", tc.path)
				dao10AssertExtras(t, points, tc.pps, tc.bps)
			})
		}
	})
}

func dao10RequireColumns(t *testing.T, db *PGStore, expected []string) {
	t.Helper()
	rows, err := db.pool.Query(context.Background(), `SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='ts_stats_5min'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatal(err)
		}
		got[column] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, column := range expected {
		if !got[column] {
			t.Errorf("ts_stats_5min missing column %s", column)
		}
	}
}

func dao10InsertRows(t *testing.T, db *PGStore, base time.Time, node string, pps, bps []string) {
	t.Helper()
	for i, row := range []struct {
		seconds int
		prefix  string
	}{{0, "192.0.2.0/25"}, {0, "192.0.2.128/25"}, {5, "192.0.2.0/25"}, {300, "192.0.2.0/25"}} {
		_, err := db.pool.Exec(context.Background(), `INSERT INTO ts_stats(time,node_id,prefix,direction,extra_decoder_pps,extra_decoder_bps) VALUES($1,$2,$3::cidr,'receives',$4::jsonb,$5::jsonb)`, base.Add(time.Duration(row.seconds)*time.Second), node, row.prefix, pps[i], bps[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.pool.Exec(context.Background(), `CALL refresh_continuous_aggregate('ts_stats_5min',$1::timestamptz,$2::timestamptz)`, base, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func dao10QueryPath(t *testing.T, r *statsRepo, base time.Time, node, path string) []store.TimeseriesPoint {
	t.Helper()
	var resolution string
	cagg := false
	switch path {
	case "cagg_5min":
		resolution, cagg = "5min", true
	case "cagg_1h":
		resolution, cagg = "1h", true
	case "raw_5s":
		resolution = "5s"
	case "raw_5min":
		resolution = "5min"
	case "raw_1h":
		resolution = "1h"
	default:
		t.Fatal(fmt.Sprintf("unknown query path %s", path))
	}
	filter := store.TimeseriesFilter{NodeID: node, From: base, To: base.Add(time.Hour), Resolution: resolution, IncludeExtras: true}
	var points []store.TimeseriesPoint
	var err error
	if cagg {
		points, err = r.queryTimeseriesFromCagg(context.Background(), filter, 100)
	} else {
		points, err = r.queryTimeseriesFromRaw(context.Background(), filter, 100)
	}
	if err != nil {
		t.Fatalf("direct %s: %v", path, err)
	}
	return points
}

func dao10AssertExtras(t *testing.T, points []store.TimeseriesPoint, pps, bps []string) {
	t.Helper()
	if len(points) != len(pps) || len(pps) != len(bps) {
		t.Fatalf("points=%d, expected PPS/BPS buckets=%d/%d", len(points), len(pps), len(bps))
	}
	for i, p := range points {
		var wantPPS map[string]int32
		var wantBPS map[string]int64
		if err := json.Unmarshal([]byte(pps[i]), &wantPPS); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(bps[i]), &wantBPS); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(p.ExtraDecoderPPS, wantPPS) {
			t.Errorf("bucket %d PPS=%v, want=%v", i, p.ExtraDecoderPPS, wantPPS)
		}
		if !reflect.DeepEqual(p.ExtraDecoderBPS, wantBPS) {
			t.Errorf("bucket %d BPS=%v, want=%v", i, p.ExtraDecoderBPS, wantBPS)
		}
	}
}
