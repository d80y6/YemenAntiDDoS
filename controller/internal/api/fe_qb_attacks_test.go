package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestFEQB_W14_ListAttacksCount(t *testing.T) {
	for _, tc := range []struct {
		name     string
		countErr error
		status   int
	}{
		{"CountFailure", errors.New("count unavailable"), http.StatusInternalServerError},
		{"CountSuccess", nil, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &q0Store{
				attacks:  []store.Attack{{ID: 41, DstIP: "192.0.2.41"}, {ID: 42, DstIP: "192.0.2.42"}},
				countErr: tc.countErr,
				// Count (3) differs from the page length (2): total must come from Count.
				countTotal: 3,
			}
			d := q0Deps(s, nil)
			r := NewRouter(d)
			req := httptest.NewRequest(http.MethodGet, "/api/attacks", nil)
			req.Header.Set("X-API-Key", d.APIKey)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Errorf("status=%d want=%d body=%s", w.Code, tc.status, w.Body)
			}
			body := q0JSON(t, w.Body.Bytes())
			wantFilters := []store.AttackFilter{{Limit: 50, Offset: 0}}
			q0Equal(t, "List calls and filter", s.listFilters, wantFilters)
			q0Equal(t, "Count calls and filter", s.countFilters, wantFilters)
			if tc.countErr != nil {
				if _, present := body["attacks"]; present {
					t.Errorf("Count failure response must have no attacks key: %s", w.Body)
				}
				q0Equal(t, "database error response", body["error"], "database error")
				return
			}
			q0Equal(t, "total from Count, not page length", body["total"], float64(3))
			attacks, ok := body["attacks"].([]any)
			if !ok || len(attacks) != 2 {
				t.Fatalf("successful List must remain nonempty: %s", w.Body)
			}
		})
	}
}
