package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// Exercise the real router without opening a listener. Every rejected request
// must preserve the previously stored row, including its repository metadata.
func TestDao9aPreconditions(t *testing.T) {
	cases := []struct {
		name      string
		attribute string
		operator  string
		value     string
		status    int
	}{
		{"G1", "carpet_bomb", "eq", "true", http.StatusOK},
		{"G2/neq_false", "carpet_bomb", "neq", "false", http.StatusOK},
		{"G2/eq_trim_upper", "carpet_bomb", "eq", " TRUE ", http.StatusOK},
		{"G2/eq_1", "carpet_bomb", "eq", "1", http.StatusOK},
		{"G2/eq_yes", "carpet_bomb", "eq", "yes", http.StatusOK},
		{"G2/eq_no", "carpet_bomb", "eq", "no", http.StatusOK},
		{"G2/eq_0", "carpet_bomb", "eq", "0", http.StatusOK},
		{"G2b", "CARPET_BOMB", "eq", "true", http.StatusBadRequest},
		{"G3/gt", "carpet_bomb", "gt", "true", http.StatusBadRequest},
		{"G3/in", "carpet_bomb", "in", "true", http.StatusBadRequest},
		{"G4/maybe", "carpet_bomb", "eq", "maybe", http.StatusBadRequest},
		{"G4/2", "carpet_bomb", "eq", "2", http.StatusBadRequest},
		{"G5/pps", "pps", "gt", "1000", http.StatusOK},
		{"G5/domain", "domain", "eq", "subnet", http.StatusOK},
		{"G5/unknown", "foo", "eq", "1", http.StatusBadRequest},
		{"G6b", "carpet_bomb", "eq", "true", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ms := NewMockStore()
			const actionID = 9
			seed := []store.ActionPrecondition{{Attribute: "pps", Operator: "gt", Value: "1000"}}
			if err := ms.Preconditions().ReplaceAll(ctx, actionID, seed); err != nil {
				t.Fatal(err)
			}
			before, err := ms.Preconditions().List(ctx, actionID)
			if err != nil || len(before) != 1 {
				t.Fatalf("seed List = %+v, err = %v", before, err)
			}
			condition := store.ActionPrecondition{Attribute: tc.attribute, Operator: tc.operator, Value: tc.value}
			body, err := json.Marshal(map[string]any{"preconditions": []store.ActionPrecondition{condition}})
			if err != nil {
				t.Fatal(err)
			}
			r := setupRouter(ms)
			req := httptest.NewRequest(http.MethodPut, "/api/actions/9/preconditions", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Errorf("PUT status = %d, want %d; body = %s", w.Code, tc.status, w.Body.String())
			}
			after, err := ms.Preconditions().List(ctx, actionID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.status == http.StatusBadRequest {
				if !reflect.DeepEqual(after, before) {
					t.Errorf("rejected PUT changed stored preconditions: before = %+v, after = %+v", before, after)
				}
				return
			}
			if len(after) != 1 {
				t.Fatalf("Preconditions().List count = %d, want 1; rows = %+v", len(after), after)
			}
			got := after[0]
			if got.Attribute != condition.Attribute || got.Operator != condition.Operator || got.Value != condition.Value {
				t.Errorf("round trip attribute/operator/value = %q/%q/%q, want %q/%q/%q", got.Attribute, got.Operator, got.Value, condition.Attribute, condition.Operator, condition.Value)
			}
		})
	}
}
