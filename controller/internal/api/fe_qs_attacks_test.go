package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestFEQS_G1_AttackSort(t *testing.T) {
	for _, sort := range []string{"", "started_at", "peak_pps", "other", "peak_pps; DROP TABLE attacks", "PEAK_PPS"} {
		t.Run("sort="+sort, func(t *testing.T) {
			s := &q0Store{countTotal: 3}
			d := q0Deps(s, nil)
			path := "/api/attacks?status=active&direction=sends&dst_ip=192.0.2.0%2F24&limit=7&offset=2" +
				"&prefix_id=4&from=2026-10-01T00:00:00Z&to=2026-10-02T00:00:00Z&ended_after=2026-10-01T00:00:00Z"
			if sort != "" {
				path += "&sort=" + url.QueryEscape(sort)
			}
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("X-API-Key", d.APIKey)
			w := httptest.NewRecorder()
			NewRouter(d).ServeHTTP(w, req)
			if sort != "" && sort != "started_at" && sort != "peak_pps" {
				q0Equal(t, "invalid sort status", w.Code, http.StatusBadRequest)
				q0Equal(t, "invalid sort error", q0JSON(t, w.Body.Bytes())["error"], "sort must be 'started_at' or 'peak_pps'")
				q0Equal(t, "invalid sort List calls", len(s.listFilters), 0)
				q0Equal(t, "invalid sort Count calls", len(s.countFilters), 0)
				return
			}
			q0Equal(t, "valid sort status", w.Code, http.StatusOK)
			from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
			to := from.Add(24 * time.Hour)
			prefix := 4
			want := []store.AttackFilter{{Sort: sort, Status: "active", Direction: "sends", DstIP: "192.0.2.0/24",
				Limit: 7, Offset: 2, PrefixID: &prefix, TimeFrom: &from, TimeTo: &to, EndedAfter: &from}}
			q0Equal(t, "List exact filter", s.listFilters, want)
			q0Equal(t, "Count exact filter", s.countFilters, want)
		})
	}
}
