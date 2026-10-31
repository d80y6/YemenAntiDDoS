package api

import (
	"context"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"reflect"
	"strings"
	"testing"
)

func TestDao13d_R0Fixed(t *testing.T) {
	t.Run("D6-C", func(t *testing.T) {
		s := dao3WebhookStore()
		s.connectors[0].Global = true
		s.connectors[0].Enabled = true
		globals := func() []store.WebhookConnector {
			rows, err := s.WebhookConnectors().List(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var result []store.WebhookConnector
			for _, r := range rows {
				if r.Global && r.Enabled {
					result = append(result, r)
				}
			}
			return result
		}
		initial := globals()
		if len(initial) != 1 {
			t.Fatal("global filter positive control failed")
		}
		before, err := s.Webhooks().List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, method := range []string{"POST", "PUT", "DELETE"} {
			t.Run(method, func(t *testing.T) {
				path := "/api/webhooks"
				if method != "POST" {
					path += "/1"
				}
				w := dao3Call(t, s, method, path, map[string]any{"url": "https://hooks.example/a", "headers": map[string]string{"Authorization": "Bearer t0ken"}})
				dao3Status(t, w, 410)
				if !strings.Contains(w.Body.String(), "/api/settings/webhook-connectors") {
					t.Error("D6-C connector guidance missing")
				}
				after, err := s.Webhooks().List(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(initial, globals()) {
					t.Error("D6-C retired write changed storage")
				}
				audit, err := s.AuditLog().List(context.Background(), store.AuditFilter{})
				if err != nil {
					t.Fatal(err)
				}
				if len(audit) != 0 {
					t.Error("D6-C retired write created audit rows")
				}
			})
		}
		t.Run("GET", func(t *testing.T) {
			w := dao3Call(t, s, "GET", "/api/webhooks", nil)
			dao3Status(t, w, 200)
			dao3Secret(t, w.Body.String())
			if !strings.Contains(w.Body.String(), "******") {
				t.Error("D6-C mask missing")
			}
		})
	})
}
