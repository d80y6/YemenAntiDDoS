package postgres

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/d80y6/YemenDDoS/controller/internal/api"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestDao14e1_RealDB_R1(t *testing.T) {
	db := newPostgresContractBackend(t).Store().(*PGStore)
	ctx := context.Background()
	t1 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	for i, at := range []time.Time{t1, t2, t1.Add(2 * time.Hour)} {
		id := 9001 + i
		tag, err := db.Pool().Exec(ctx, `INSERT INTO config_audit_log (id, user_id, entity_type, entity_id, action, diff, created_at) VALUES ($1, NULL, 'dao14e1', 'r1', 'update', '{}'::jsonb, $2)`, id, at)
		if err != nil {
			t.Fatalf("DEVICE insert audit id=%d: %v", id, err)
		}
		if tag.RowsAffected() != 1 {
			t.Fatalf("DEVICE insert audit id=%d affected=%d want=1", id, tag.RowsAffected())
		}
	}
	for _, tc := range []struct {
		name     string
		from, to *time.Time
		ids      []int
	}{
		{"NoWindow", nil, nil, []int{9003, 9002, 9001}},
		{"Window", &t2, &t2, []int{9002}},
		{"FromOnly", &t2, nil, []int{9003, 9002}},
		{"ToOnly", nil, &t2, []int{9002, 9001}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := db.AuditLog().List(ctx, store.AuditFilter{EntityType: "dao14e1", TimeFrom: tc.from, TimeTo: tc.to})
			if err != nil {
				t.Fatalf("list audit: %v", err)
			}
			ids := make([]int, len(rows))
			for i, row := range rows {
				ids[i] = row.ID
			}
			if !reflect.DeepEqual(ids, tc.ids) {
				t.Errorf("audit IDs=%v want=%v", ids, tc.ids)
			}
		})
	}
}

func TestDao14e1_RealDB_R2(t *testing.T) {
	db := newPostgresContractBackend(t).Store().(*PGStore)
	ctx := context.Background()
	from := time.Now().Add(-time.Hour)
	router := api.NewRouter(api.Dependencies{Store: db, APIKey: "dao14e1"})
	for _, prefix := range []string{"abc", "198.51.100.1/24"} {
		t.Run(prefix, func(t *testing.T) {
			t.Run("Repo", func(t *testing.T) {
				_, err := db.Stats().QueryTotalTimeseries(ctx, store.TimeseriesFilter{Prefix: prefix, Resolution: "5s", From: from, Limit: 7200})
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) {
					t.Fatalf("prefix=%q error=%v want PostgreSQL 22P02", prefix, err)
				}
				if pgErr.Code != "22P02" {
					t.Errorf("prefix=%q SQLSTATE=%s want=22P02", prefix, pgErr.Code)
				}
			})
			t.Run("HTTP", func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/api/stats/total-timeseries?resolution=5s&prefix="+url.QueryEscape(prefix), nil)
				req.Header.Set("X-API-Key", "dao14e1")
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest || w.Body.String() != `{"error":"invalid input"}` {
					t.Errorf("prefix=%q status=%d body=%s want status=400 body=%s", prefix, w.Code, w.Body.String(), `{"error":"invalid input"}`)
				}
			})
		})
	}
}

func TestDao14e1_RealDB_R3(t *testing.T) {
	db := newPostgresContractBackend(t).Store().(*PGStore)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Minute).Add(-10 * time.Minute)
	for _, seed := range []struct {
		node, prefix string
		pps          int64
	}{
		{"dao14e1-a", "198.51.100.0/25", 1},
		{"dao14e1-a", "198.51.100.128/25", 10},
		{"dao14e1-b", "198.51.100.0/25", 100},
		{"dao14e1-b", "198.51.100.128/25", 1000},
		{"dao14e1-a", "203.0.113.0/24", 10000},
	} {
		tag, err := db.Pool().Exec(ctx, `INSERT INTO ts_stats (time, node_id, dst_ip, prefix, direction, pps, bps) VALUES ($1, $2, NULL, $3::cidr, 'receives', $4, 0)`, at, seed.node, seed.prefix, seed.pps)
		if err != nil {
			t.Fatalf("DEVICE insert stats node=%s prefix=%s: %v", seed.node, seed.prefix, err)
		}
		if tag.RowsAffected() != 1 {
			t.Fatalf("DEVICE insert stats node=%s prefix=%s affected=%d want=1", seed.node, seed.prefix, tag.RowsAffected())
		}
	}
	for _, tc := range []struct {
		name, node, prefix string
		pps                int64
	}{
		{"NoFilter", "", "", 11111},
		{"Node", "dao14e1-a", "", 10011},
		{"Prefix", "", "198.51.100.0/25", 101},
		{"NodeAndPrefix", "dao14e1-b", "198.51.100.128/25", 1000},
		{"PrefixContains", "", "198.51.100.0/24", 1111},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filter := store.TimeseriesFilter{Resolution: "5s", Direction: "receives", Limit: 7200, From: at.Add(-time.Minute), To: at.Add(time.Minute), NodeID: tc.node, Prefix: tc.prefix}
			points, err := db.Stats().QueryTotalTimeseries(ctx, filter)
			if err != nil {
				t.Fatalf("query total timeseries: %v", err)
			}
			if len(points) != 1 {
				t.Fatalf("timeseries points=%d want=1; points=%+v", len(points), points)
			}
			if points[0].PPS != tc.pps {
				t.Errorf("PPS=%d want=%d", points[0].PPS, tc.pps)
			}
		})
	}
}
