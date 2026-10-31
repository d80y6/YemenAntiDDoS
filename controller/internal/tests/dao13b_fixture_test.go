package tests

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDao13b_F1(t *testing.T) {
	r := setupRouter(NewMockStore())
	for _, tc := range []struct{ method, body string }{
		{"GET", ""},
		{"POST", `{"username":"fixture-user","password":"fixture-pass","role":"viewer"}`},
	} {
		t.Run(tc.method, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/users", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if tc.method == "GET" && w.Code != 200 {
				t.Errorf("fixture GET status=%d body=%s; want 200", w.Code, w.Body)
			}
			if tc.method == "POST" && (w.Code == 401 || w.Code == 403) {
				t.Errorf("fixture POST rejected: status=%d body=%s", w.Code, w.Body)
			}
		})
	}
}
