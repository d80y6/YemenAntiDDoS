package postgres

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func TestDao14b2_P5(t *testing.T) {
	for _, name := range []string{"HourP95", "WindowP95", "MinPointsCountsInboundOnly"} {
		t.Run(name, func(t *testing.T) {
			s := newPostgresContractBackend(t).Store()
			db := s.(*PGStore)
			ctx := context.Background()
			end := time.Now().UTC().Truncate(time.Hour)
			start := end.Add(-time.Hour)
			var points []store.StatPoint
			add := func(prefix, direction string, pps int64, count int) {
				for i := 0; i < count; i++ {
					points = append(points, store.StatPoint{Time: start.Add(time.Duration(i+1) * time.Second), NodeID: "n1", Prefix: &prefix, Direction: direction, PPS: pps, BPS: pps * 8})
				}
			}
			add("198.51.100.192/26", "receives", 800, 120)
			add("198.51.100.192/26", "sends", 3000, 120)
			add("198.51.100.0/26", "sends", 3000, 120)
			add("198.51.100.64/26", "", 700, 120)
			add("198.51.100.128/26", "receives", 800, 60)
			add("198.51.100.128/26", "sends", 3000, 60)
			if err := s.Stats().BulkInsert(ctx, points); err != nil {
				t.Fatal(err)
			}
			rows, err := db.Pool().Query(ctx, `SELECT direction, count(*) FROM ts_stats WHERE prefix = $1::inet GROUP BY direction`, "198.51.100.192/26")
			if err != nil {
				t.Fatal(err)
			}
			counts := map[string]int{}
			for rows.Next() {
				var direction string
				var count int
				if err := rows.Scan(&direction, &count); err != nil {
					rows.Close()
					t.Fatal(err)
				}
				counts[direction] = count
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(counts, map[string]int{"receives": 120, "sends": 120}) {
				t.Fatalf("direction fixture=%v", counts)
			}
			check := func(results []store.P95Result, err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
				byPrefix := map[string]store.P95Result{}
				for _, row := range results {
					if _, exists := byPrefix[row.Prefix]; exists {
						t.Errorf("duplicate P95 prefix %s", row.Prefix)
					}
					byPrefix[row.Prefix] = row
				}
				if name == "MinPointsCountsInboundOnly" {
					if row, exists := byPrefix["198.51.100.128/26"]; exists {
						t.Errorf("outbound points met inbound minimum: %+v", row)
					}
					return
				}
				for prefix, pps := range map[string]int64{"198.51.100.192/26": 800, "198.51.100.64/26": 700} {
					row, exists := byPrefix[prefix]
					if !exists || row.NodeID != "n1" || row.P95PPS != pps || row.P95BPS != pps*8 || row.DataPoints != 120 {
						t.Errorf("P95 %s=%+v exists=%v; want n1/%d/%d/120", prefix, row, exists, pps, pps*8)
					}
				}
				if row, exists := byPrefix["198.51.100.0/26"]; exists {
					t.Errorf("outbound-only prefix returned: %+v", row)
				}
			}
			if name != "WindowP95" {
				check(s.Stats().QueryHourP95(ctx, start, end, 100))
			}
			if name != "HourP95" {
				check(s.Stats().QueryWindowP95(ctx, end, time.Hour, 100))
			}
		})
	}
}
