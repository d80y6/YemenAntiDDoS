package api

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/configpub"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/threshold"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus"
)

type dao12cStore struct {
	*dao11cStore
	prefixFail, nodeFail, prefixCalls, nodeCalls int
}
type dao12cPrefixes struct {
	store.PrefixRepo
	s *dao12cStore
}
type dao12cNodes struct {
	store.NodeRepo
	s *dao12cStore
}

func (s *dao12cStore) Users() store.UserRepo {
	return dao12cUsers{user: &store.User{
		ID: 1, Username: "operator", Role: "admin", Enabled: true,
		UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}}
}

func (s *dao12cStore) Prefixes() store.PrefixRepo {
	return dao12cPrefixes{s.dao11cStore.Prefixes(), s}
}
func (s *dao12cStore) Nodes() store.NodeRepo { return dao12cNodes{s.dao11cStore.Nodes(), s} }
func (r dao12cPrefixes) List(c context.Context) ([]store.WatchPrefix, error) {
	r.s.prefixCalls++
	if r.s.prefixCalls == r.s.prefixFail {
		return nil, errors.New("injected prefix list failure")
	}
	return r.PrefixRepo.List(c)
}
func (r dao12cNodes) List(c context.Context) ([]store.Node, error) {
	r.s.nodeCalls++
	if r.s.nodeCalls == r.s.nodeFail {
		return nil, errors.New("injected node list failure")
	}
	return r.NodeRepo.List(c)
}

func dao12cPublishRequest(t *testing.T, s *dao12cStore) (*httptest.ResponseRecorder, string) {
	t.Helper()
	user, _ := s.Users().Get(context.Background(), 1)
	token, err := generateJWT("dao12c-secret", user)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("PUT", "/api/prefixes/1", strings.NewReader(`{"name":"updated"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	deps := Dependencies{Store: s, JWTSecret: "dao12c-secret", ThreshTree: &threshold.Tree{}, ConfigPub: configpub.New(s, nil, func() []string { return nil })}
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	rec := httptest.NewRecorder()
	NewRouter(deps).ServeHTTP(rec, req)
	return rec, logs.String()
}

func dao12cGather(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	t.Helper()
	fs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	for _, f := range fs {
		if f.GetName() == "xsight_config_publish_failures_total" {
			for _, m := range f.Metric {
				for _, l := range m.Label {
					if l.GetName() == "stage" {
						values[l.GetValue()] = m.GetCounter().GetValue()
					}
				}
			}
		}
	}
	return values
}

func TestDao12c_G1(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		prefixFail, nodeFail int
	}{{"G1a", 1, 0}, {"G1b", 0, 1}, {"G1c", 0, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			if err := metrics.Register(reg, dao5APIStore{}, &tracker.Tracker{}); err != nil {
				t.Fatal(err)
			}
			before := dao12cGather(t, reg)
			if tc.name == "G1c" {
				t.Run("Registered", func(t *testing.T) {
					for _, stage := range []string{"rebuild", "publish"} {
						if _, ok := before[stage]; !ok {
							t.Errorf("registered metric missing stage=%s", stage)
						}
					}
				})
			}
			control, _ := dao12cPublishRequest(t, &dao12cStore{dao11cStore: dao11cFixture()})
			// Re-baseline after the control request so its counts cannot offset the injected request.
			base := dao12cGather(t, reg)
			s := &dao12cStore{dao11cStore: dao11cFixture(), prefixFail: tc.prefixFail, nodeFail: tc.nodeFail}
			auditsBefore := len(s.audits)
			rec, logs := dao12cPublishRequest(t, s)
			after := dao12cGather(t, reg)
			rebuild, publish := after["rebuild"]-base["rebuild"], after["publish"]-base["publish"]
			if tc.name != "G1c" {
				t.Run("Resp", func(t *testing.T) {
					dao11cEqual(t, control.Code, 200)
					dao11cEqual(t, rec.Code, 200)
					dao11cEqual(t, rec.Body.String(), `{"ok":true}`)
				})
			}
			t.Run("Log", func(t *testing.T) {
				needle, want := "ERROR", 0
				if tc.name == "G1a" {
					needle, want = "ERROR api: rebuild threshold tree", 1
				} else if tc.name == "G1b" {
					needle, want = "ERROR api: publish config", 1
				}
				count := 0
				for _, line := range strings.Split(logs, "\n") {
					if strings.Contains(line, needle) {
						count++
					}
				}
				dao11cEqual(t, count, want)
			})
			t.Run("Metric", func(t *testing.T) {
				want := map[string][2]float64{"G1a": {1, 0}, "G1b": {0, 1}, "G1c": {0, 0}}[tc.name]
				dao11cEqual(t, [2]float64{rebuild, publish}, want)
			})
			if tc.name == "G1a" {
				t.Run("Total", func(t *testing.T) { dao11cEqual(t, rebuild+publish, float64(1)) })
				t.Run("StillPublishes", func(t *testing.T) { dao11cEqual(t, len(s.audits)-auditsBefore, 1) })
			}
		})
	}
}
