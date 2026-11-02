package postgres

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// Reuse the established disposable-database fixture. It skips before connecting
// when XSIGHT_TEST_ADMIN_DSN is absent. No production database is addressed.
func q0PG(t *testing.T) *PGStore {
	t.Helper()
	return newPostgresContractBackend(t).(*postgresContractBackend).db
}
func q0PGCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func q0PGValues(t *testing.T, points []store.TimeseriesPoint, pps, bps int64) {
	t.Helper()
	if len(points) != 1 {
		t.Fatalf("buckets=%d want=1: %+v", len(points), points)
	}
	if points[0].PPS != pps || points[0].BPS != bps {
		t.Fatalf("pps/bps=(%d,%d) want=(%d,%d)", points[0].PPS, points[0].BPS, pps, bps)
	}
}

func TestFEQ0_G3_B1(t *testing.T) {
	db := q0PG(t)
	ctx := context.Background()
	r := db.Stats()
	base := time.Now().UTC().Truncate(5 * time.Minute).Add(-20 * time.Minute)
	ip, other, prefix := "192.0.2.10", "192.0.2.11", "192.0.2.0/24"
	// Same timestamp across nodes: X=10+20=30. A second timestamp in
	// the same 5-minute bucket contributes 50: (30+50)/2=40, not 80.
	input := []store.StatPoint{
		{Time: base, NodeID: "q0-n1", Prefix: &prefix, PPS: 100, BPS: 1000},
		{Time: base, NodeID: "q0-n1", DstIP: &ip, PPS: 10, BPS: 100},
		{Time: base, NodeID: "q0-n2", DstIP: &ip, PPS: 20, BPS: 200},
		{Time: base, NodeID: "q0-n1", DstIP: &other, PPS: 90, BPS: 900},
		{Time: base.Add(5 * time.Second), NodeID: "q0-n1", DstIP: &ip, PPS: 50, BPS: 500},
		{Time: base, NodeID: "q0-n1", DstIP: &ip, Direction: "sends", PPS: 70, BPS: 700},
	}
	q0PGCheck(t, r.BulkInsert(ctx, input))
	for _, tc := range []struct {
		name     string
		filter   store.TimeseriesFilter
		pps, bps int64
	}{
		{"Raw5s", store.TimeseriesFilter{DstIP: ip, From: base, To: base.Add(time.Second), Resolution: "5s"}, 30, 300},
		{"WithoutDstIP_P", store.TimeseriesFilter{From: base, To: base.Add(time.Second), Resolution: "5s"}, 100, 1000},
		{"Raw5minTwoStage", store.TimeseriesFilter{DstIP: ip, From: base, To: base.Add(time.Minute), Resolution: "5min"}, 40, 400},
		{"NodeFilter", store.TimeseriesFilter{DstIP: ip, NodeID: "q0-n1", From: base, To: base.Add(time.Second), Resolution: "5s"}, 10, 100},
		{"Outbound", store.TimeseriesFilter{DstIP: ip, Direction: "sends", From: base, To: base.Add(time.Second), Resolution: "5s"}, 70, 700},
	} {
		t.Run(tc.name, func(t *testing.T) {
			points, err := r.QueryTimeseries(ctx, tc.filter)
			q0PGCheck(t, err)
			q0PGValues(t, points, tc.pps, tc.bps)
		})
	}
	t.Run("TotalTimeseries", func(t *testing.T) {
		points, err := r.QueryTotalTimeseries(ctx, store.TimeseriesFilter{DstIP: ip, From: base, To: base.Add(time.Second), Resolution: "5s"})
		q0PGCheck(t, err)
		q0PGValues(t, points, 30, 300)
	})

	t.Run("ForceRaw", func(t *testing.T) {
		old := time.Now().UTC().Add(-2 * time.Hour).Truncate(5 * time.Minute)
		if time.Since(old) <= 90*time.Minute {
			t.Fatal("fixture must select public cagg branch without DstIP")
		}
		q0PGCheck(t, r.BulkInsert(ctx, []store.StatPoint{
			{Time: old, NodeID: "q0-n1", Prefix: &prefix, PPS: 120, BPS: 1200},
			{Time: old, NodeID: "q0-n1", DstIP: &ip, PPS: 15, BPS: 150},
			{Time: old, NodeID: "q0-n2", DstIP: &ip, PPS: 30, BPS: 300},
		}))
		_, err := db.pool.Exec(ctx, `CALL refresh_continuous_aggregate('ts_stats_5min',$1::timestamptz,$2::timestamptz)`, old, old.Add(5*time.Minute))
		q0PGCheck(t, err)
		for _, tc := range []struct {
			name, ip string
			pps, bps int64
		}{{"CaggPositiveWithoutDstIP", "", 120, 1200}, {"DstIPMustUseRaw", ip, 45, 450}} {
			t.Run(tc.name, func(t *testing.T) {
				filter := store.TimeseriesFilter{DstIP: tc.ip, From: old, To: old.Add(5*time.Minute - time.Second), Resolution: "5min"}
				var points []store.TimeseriesPoint
				var queryErr error
				logs := dao14d2Capture(t, func() { points, queryErr = r.QueryTimeseries(ctx, filter) })
				q0PGCheck(t, queryErr)
				if strings.Contains(logs, "cagg query failed") {
					t.Fatalf("cagg fallback must be absent: %s", logs)
				}
				if tc.ip != "" && len(points) == 1 && points[0].PPS == 120 {
					t.Fatalf("dst_ip returned prefix P=120; want IP X=45")
				}
				q0PGValues(t, points, tc.pps, tc.bps)
			})
		}
	})
}

func q0PGAttack(t *testing.T, db *PGStore, ip string, start time.Time, end *time.Time) int {
	t.Helper()
	ctx := context.Background()
	a := &store.Attack{DstIP: ip, Direction: "receives", DecoderFamily: "udp", AttackType: "udp_flood", Severity: "high", Confidence: 1, StartedAt: start, ReasonCodes: []string{}, NodeSources: []string{"q0"}}
	id, err := db.Attacks().Create(ctx, a)
	q0PGCheck(t, err)
	if end != nil {
		a.ID = id
		a.EndedAt = end
		q0PGCheck(t, db.Attacks().Update(ctx, a))
	}
	return id
}

func TestFEQ0_G3_B4(t *testing.T) {
	db := q0PG(t)
	ctx := context.Background()
	now := time.Now().UTC()
	host := q0PGAttack(t, db, "198.51.100.7", now, nil)
	network := q0PGAttack(t, db, "198.51.100.0/24", now, nil)
	q0PGAttack(t, db, "203.0.113.9", now, nil)
	for _, tc := range []struct {
		name, target string
		ids          []int
		count        int
	}{{"Host", "198.51.100.7", []int{host}, 1}, {"Network", "198.51.100.0/24", []int{host, network}, 2}} {
		t.Run(tc.name, func(t *testing.T) {
			filter := store.AttackFilter{DstIP: tc.target}
			rows, err := db.Attacks().List(ctx, filter)
			q0PGCheck(t, err)
			count, err := db.Attacks().Count(ctx, filter)
			q0PGCheck(t, err)
			var ids []int
			for _, row := range rows {
				ids = append(ids, row.ID)
			}
			sort.Ints(ids)
			sort.Ints(tc.ids)
			if len(rows) != tc.count || count != tc.count || !reflect.DeepEqual(ids, tc.ids) {
				t.Fatalf("targets=%v count=%d want ids=%v count=%d", ids, count, tc.ids, tc.count)
			}
		})
	}
}

func TestFEQ0_G3_B11(t *testing.T) {
	db := q0PG(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 10, 27, 13, 0, 0, 0, time.UTC)
	before := time.Date(2026, 10, 27, 11, 0, 0, 0, time.UTC)
	inside := time.Date(2026, 10, 27, 12, 30, 0, 0, time.UTC)
	ended := q0PGAttack(t, db, "192.0.2.1", before, &inside)
	unfinished := q0PGAttack(t, db, "192.0.2.2", before, nil)
	q0PGAttack(t, db, "192.0.2.3", before, &before)
	started := q0PGAttack(t, db, "192.0.2.4", inside, &t1)
	filter := store.AttackFilter{EndedAfter: &t0, TimeTo: &t1}
	rows, err := db.Attacks().List(ctx, filter)
	q0PGCheck(t, err)
	count, err := db.Attacks().Count(ctx, filter)
	q0PGCheck(t, err)
	var ids []int
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	sort.Ints(ids)
	want := []int{ended, unfinished, started}
	sort.Ints(want)
	if len(rows) != 3 || count != 3 || !reflect.DeepEqual(ids, want) {
		t.Fatalf("overlap ids=%v count=%d want ids=%v count=3 (unfinished attack must remain)", ids, count, want)
	}
}
