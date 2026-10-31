package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func TestDao14e1_CB02(t *testing.T) {
	for _, tc := range []struct {
		name, body, description string
	}{
		{"ExplicitEmpty", `{"name":"n1","bgp_asn":65000,"vtysh_path":"/usr/bin/vtysh","description":"","enabled":true}`, ""},
		{"Null", `{"description":null}`, "d-old"},
		{"Omitted", `{"enabled":true}`, "d-old"},
		{"NewValue", `{"description":"d-new"}`, "d-new"},
		{"OtherStringsUnchanged", `{"name":"","vtysh_path":"","address_family":""}`, "d-old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dao11cFixture()
			s.bgps.rows[0].Description = "d-old"
			s.bgps.rows[0].VtyshPath = "/usr/bin/vtysh"
			s.bgps.rows[0].AddressFamily = "auto"
			dao11cRequest(t, s, "PUT", dao11cConnectorPath("bgp", "PUT"), json.RawMessage(tc.body), http.StatusOK, "")
			row := s.bgps.rows[0]
			dao11cEqual(t, row.Description, tc.description)
			if tc.name == "OtherStringsUnchanged" {
				dao11cEqual(t, row.Name, "n1")
				dao11cEqual(t, row.VtyshPath, "/usr/bin/vtysh")
				dao11cEqual(t, row.AddressFamily, "auto")
			}
			if tc.name == "ExplicitEmpty" {
				if len(s.audits) != 1 {
					t.Fatalf("audit rows=%d want=1", len(s.audits))
				}
				var diff map[string]map[string]any
				if err := json.Unmarshal(s.audits[0].Diff, &diff); err != nil {
					t.Fatalf("decode audit diff: %v", err)
				}
				dao11cEqual(t, diff["old"]["description"], any("d-old"))
				dao11cEqual(t, diff["new"]["description"], any(""))
			}
		})
	}
}

// Unimplemented repositories deliberately remain nil: these GETs must only use
// the recorded Stats and AuditLog methods.
type dao14e1Store struct {
	store.Store
	total, plain []store.TimeseriesFilter
	audit        []store.AuditFilter
	rows         []store.AuditLog
	fault        error
}

type dao14e1Stats struct {
	store.StatsRepo
	s *dao14e1Store
}

func (s *dao14e1Store) Stats() store.StatsRepo { return &dao14e1Stats{s: s} }

func (r *dao14e1Stats) QueryTotalTimeseries(_ context.Context, f store.TimeseriesFilter) ([]store.TimeseriesPoint, error) {
	r.s.total = append(r.s.total, f)
	return nil, r.s.fault
}

func (r *dao14e1Stats) QueryTimeseries(_ context.Context, f store.TimeseriesFilter) ([]store.TimeseriesPoint, error) {
	r.s.plain = append(r.s.plain, f)
	return nil, r.s.fault
}

type dao14e1Audit struct {
	store.AuditLogRepo
	s *dao14e1Store
}

func (s *dao14e1Store) AuditLog() store.AuditLogRepo { return &dao14e1Audit{s: s} }

func (r *dao14e1Audit) List(_ context.Context, f store.AuditFilter) ([]store.AuditLog, error) {
	r.s.audit = append(r.s.audit, f)
	return r.s.rows, r.s.fault
}

func dao14e1Get(s *dao14e1Store, path string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := NewRouter(Dependencies{Store: s, APIKey: "dao14e1"})
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-API-Key", "dao14e1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func dao14e1TotalFilter(t *testing.T, s *dao14e1Store) store.TimeseriesFilter {
	t.Helper()
	if len(s.total) != 1 || len(s.plain) != 0 {
		t.Fatalf("repository calls: total=%d plain=%d want total=1 plain=0", len(s.total), len(s.plain))
	}
	return s.total[0]
}

func TestDao14e1_T03(t *testing.T) {
	for _, tc := range []struct {
		name, query, node, prefix string
		status                    int
	}{
		{"Pass", "?node_id=dao14-n1&prefix=198.51.100.0/24&direction=receives", "dao14-n1", "198.51.100.0/24", http.StatusOK},
		{"IPv6Encoded", "?prefix=2001%3Adb8%3A%3A%2F32", "", "2001:db8::/32", http.StatusOK},
		{"InvalidPrefixToStore", "?prefix=abc", "", "abc", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &dao14e1Store{}
			if tc.name == "InvalidPrefixToStore" {
				s.fault = fmt.Errorf("fixture repository: %w", &pgconn.PgError{Severity: "ERROR", Code: "22P02", Message: `invalid input syntax for type cidr: "abc"`})
			}
			w := dao14e1Get(s, "/api/stats/total-timeseries"+tc.query)
			f := dao14e1TotalFilter(t, s)
			if w.Code != tc.status {
				t.Errorf("status=%d want=%d body=%s", w.Code, tc.status, w.Body.String())
			}
			if f.NodeID != tc.node || f.Prefix != tc.prefix {
				t.Errorf("NodeID=%q Prefix=%q want NodeID=%q Prefix=%q", f.NodeID, f.Prefix, tc.node, tc.prefix)
			}
			// The injected error also produces 400 on HEAD; the Prefix check is
			// the behavior assertion that must fail before this change.
			if tc.name == "InvalidPrefixToStore" && w.Body.String() != `{"error":"invalid input"}` {
				t.Errorf("error body=%s want=%s", w.Body.String(), `{"error":"invalid input"}`)
			}
			// node_id alone must reach the repository without a prefix
			// (blind review r1 P1-1: a mutant dropping NodeID when Prefix is
			// empty survived the combined request above).
			if tc.name == "Pass" {
				s := &dao14e1Store{}
				w := dao14e1Get(s, "/api/stats/total-timeseries?node_id=dao14-n1")
				f := dao14e1TotalFilter(t, s)
				if w.Code != http.StatusOK || f.NodeID != "dao14-n1" || f.Prefix != "" {
					t.Errorf("node-only: status=%d NodeID=%q Prefix=%q want 200 NodeID=%q Prefix=%q", w.Code, f.NodeID, f.Prefix, "dao14-n1", "")
				}
			}
		})
	}
	t.Run("NoParamsAllNodes", func(t *testing.T) {
		from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
		for _, tc := range []struct {
			query string
			want  store.TimeseriesFilter
		}{
			{"", store.TimeseriesFilter{Resolution: "5min", Limit: 2000}},
			{"?node_id=&prefix=", store.TimeseriesFilter{Resolution: "5min", Limit: 2000}},
			{"?node_id=&prefix=&resolution=5s&direction=both&include_extras=true&from=2026-10-01T00:00:00Z&to=2026-10-01T01:00:00Z", store.TimeseriesFilter{Resolution: "5s", Direction: "both", Limit: 7200, IncludeExtras: true, From: from, To: from.Add(time.Hour)}},
		} {
			s := &dao14e1Store{}
			before := time.Now()
			w := dao14e1Get(s, "/api/stats/total-timeseries"+tc.query)
			after := time.Now()
			f := dao14e1TotalFilter(t, s)
			if w.Code != http.StatusOK {
				t.Errorf("query=%q status=%d body=%s", tc.query, w.Code, w.Body.String())
			}
			if tc.want.From.IsZero() {
				if f.From.Before(before.Add(-time.Hour-time.Second)) || f.From.After(after.Add(-time.Hour+time.Second)) {
					t.Errorf("query=%q default From=%v outside request-relative one-hour window", tc.query, f.From)
				}
				f.From = time.Time{}
			}
			if !reflect.DeepEqual(f, tc.want) {
				t.Errorf("query=%q filter=%+v want=%+v", tc.query, f, tc.want)
			}
		}
	})
}

func dao14e1AuditFilter(t *testing.T, s *dao14e1Store, w *httptest.ResponseRecorder) store.AuditFilter {
	t.Helper()
	if len(s.audit) != 1 || w.Code != http.StatusOK {
		t.Fatalf("audit calls=%d status=%d want calls=1 status=200 body=%s", len(s.audit), w.Code, w.Body.String())
	}
	return s.audit[0]
}

func dao14e1TimeEqual(t *testing.T, field string, got, want *time.Time) {
	t.Helper()
	if (got == nil) != (want == nil) || (got != nil && want != nil && !got.Equal(*want)) {
		t.Errorf("%s=%v want=%v", field, got, want)
	}
}

func TestDao14e1_U07(t *testing.T) {
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	userID := 1
	for _, tc := range []struct {
		name, query string
		want        store.AuditFilter
	}{
		{"Contract", "?entity_type=watch_prefix&user_id=1&from=2026-10-01T00:00:00.000Z&to=2026-10-02T00:00:00.000Z&limit=51&offset=50", store.AuditFilter{EntityType: "watch_prefix", UserID: &userID, TimeFrom: &from, TimeTo: &to, Limit: 51, Offset: 50}},
		{"FromOnly", "?from=2026-10-01T08:00:00%2B08:00", store.AuditFilter{TimeFrom: &from, Limit: 50}},
		{"ToOnly", "?to=2026-10-02T00:00:00Z", store.AuditFilter{TimeTo: &to, Limit: 50}},
		{"InvalidIgnored/From", "?from=garbage&to=2026-10-02T00:00:00Z", store.AuditFilter{TimeTo: &to, Limit: 50}},
		{"InvalidIgnored/To", "?from=2026-10-01T00:00:00Z&to=garbage", store.AuditFilter{TimeFrom: &from, Limit: 50}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &dao14e1Store{}
			w := dao14e1Get(s, "/api/audit-log"+tc.query)
			f := dao14e1AuditFilter(t, s, w)
			dao14e1TimeEqual(t, "TimeFrom", f.TimeFrom, tc.want.TimeFrom)
			dao14e1TimeEqual(t, "TimeTo", f.TimeTo, tc.want.TimeTo)
			want := tc.want
			f.TimeFrom, f.TimeTo, want.TimeFrom, want.TimeTo = nil, nil, nil, nil
			if !reflect.DeepEqual(f, want) {
				t.Errorf("filter=%+v want=%+v", f, want)
			}
			if tc.name == "Contract" && w.Body.String() != "[]" && w.Body.String() != "null" {
				t.Errorf("empty audit body=%s want=[] or null", w.Body.String())
			}
		})
	}
	t.Run("LimitClamp", func(t *testing.T) {
		for _, limit := range []int{201, 100000} {
			s := &dao14e1Store{}
			w := dao14e1Get(s, fmt.Sprintf("/api/audit-log?limit=%d", limit))
			f := dao14e1AuditFilter(t, s, w)
			if f.Limit != 200 {
				t.Errorf("limit=%d reached repository as %d want=200", limit, f.Limit)
			}
		}
	})
	t.Run("LimitBelowCap", func(t *testing.T) {
		for _, tc := range []struct {
			query string
			limit int
		}{{"?limit=51", 51}, {"?limit=200", 200}, {"", 50}, {"?limit=-1", -1}} {
			s := &dao14e1Store{}
			w := dao14e1Get(s, "/api/audit-log"+tc.query)
			f := dao14e1AuditFilter(t, s, w)
			want := store.AuditFilter{Limit: tc.limit}
			if !reflect.DeepEqual(f, want) {
				t.Errorf("query=%q filter=%+v want=%+v", tc.query, f, want)
			}
		}
	})
	t.Run("BareArrayMasked", func(t *testing.T) {
		obj := map[string]any{"headers": map[string]string{"Authorization": "Bearer t0ken"}}
		s := &dao14e1Store{rows: []store.AuditLog{{ID: 7, EntityType: "webhook_connector", Diff: makeDiff(obj, obj)}}}
		w := dao14e1Get(s, "/api/audit-log?from=2026-10-01T00:00:00Z&to=2026-10-02T00:00:00Z&limit=51")
		dao14e1AuditFilter(t, s, w)
		var rows []store.AuditLog
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatalf("expected bare JSON array: %v; body=%s", err, w.Body.String())
		}
		if len(rows) != 1 {
			t.Fatalf("audit rows=%d want=1", len(rows))
		}
		if strings.Contains(w.Body.String(), "t0ken") || !strings.Contains(w.Body.String(), "******") {
			t.Errorf("historical secret was not masked: %s", w.Body.String())
		}
	})
}
