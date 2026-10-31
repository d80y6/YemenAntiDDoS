package tests

import (
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/api"
	"github.com/littlewolf9527/xsight/controller/internal/configpub"
	"github.com/littlewolf9527/xsight/controller/internal/engine/threshold"
	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type dao13aAPIStore struct {
	*MockStore
	rows                                       []store.WatchPrefix
	lists, creates, updates, publishes, audits int
	listErr                                    bool
}
type dao13aAPIPrefixes struct {
	store.PrefixRepo
	s *dao13aAPIStore
}
type dao13aAPIAudit struct {
	store.AuditLogRepo
	s *dao13aAPIStore
}
type dao13aAPINodes struct{ store.NodeRepo }

func (s *dao13aAPIStore) Prefixes() store.PrefixRepo {
	return dao13aAPIPrefixes{s.MockStore.Prefixes(), s}
}
func (s *dao13aAPIStore) AuditLog() store.AuditLogRepo {
	return dao13aAPIAudit{s.MockStore.AuditLog(), s}
}
func (s *dao13aAPIStore) Nodes() store.NodeRepo { return dao13aAPINodes{s.MockStore.Nodes()} }
func (r dao13aAPIPrefixes) List(context.Context) ([]store.WatchPrefix, error) {
	r.s.lists++
	if r.s.listErr {
		return nil, errors.New("injected preflight list failure")
	}
	return append([]store.WatchPrefix(nil), r.s.rows...), nil
}
func (r dao13aAPIPrefixes) Get(_ context.Context, id int) (*store.WatchPrefix, error) {
	for _, p := range r.s.rows {
		if p.ID == id {
			return &p, nil
		}
	}
	return nil, errors.New("prefix not found")
}
func (r dao13aAPIPrefixes) Create(_ context.Context, p *store.WatchPrefix) (int, error) {
	r.s.creates++
	cp := *p
	cp.ID = 10 + r.s.creates
	r.s.rows = append(r.s.rows, cp)
	return cp.ID, nil
}
func (r dao13aAPIPrefixes) Update(_ context.Context, p *store.WatchPrefix) error {
	r.s.updates++
	for i := range r.s.rows {
		if r.s.rows[i].ID == p.ID {
			r.s.rows[i] = *p
			return nil
		}
	}
	return errors.New("prefix not found")
}
func (r dao13aAPIAudit) Create(context.Context, *store.AuditLog) error {
	r.s.audits++
	return nil
}
func (r dao13aAPINodes) List(context.Context) ([]store.Node, error) {
	return []store.Node{{ID: "dao13a-node", Enabled: true, Mode: "xdp"}}, nil
}
func (s *dao13aAPIStore) SendConfigPush(string, *pb.WatchConfig, uint64) error {
	s.publishes++
	return nil
}

func dao13aAPIRequest(t *testing.T, s *dao13aAPIStore, publish bool, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	deps := api.Dependencies{Store: s, JWTSecret: testJWTSecret}
	if publish {
		deps.ThreshTree = threshold.NewTree()
		deps.ConfigPub = configpub.New(s, s, func() []string { return []string{"dao13a-node"} })
	}
	path := "/api/prefixes"
	if method == "PUT" {
		path += "/1"
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	rec := httptest.NewRecorder()
	api.NewRouter(deps).ServeHTTP(rec, req)
	return rec
}

func dao13aAPIBase() *dao13aAPIStore {
	return &dao13aAPIStore{MockStore: NewMockStore(), rows: []store.WatchPrefix{
		{ID: 1, Prefix: "192.0.2.0/24", Enabled: true},
		{ID: 2, Prefix: "198.51.100.0/24", Enabled: true},
		{ID: 3, Prefix: "203.0.113.0/24", Enabled: true},
	}}
}

func TestDao13a_C2(t *testing.T) {
	for _, tc := range []struct {
		name, method, body, message string
		status                      int
		badCycle, listErr           bool
	}{
		{"SelfCycle_400_NoWrites", "PUT", `{"parent_id":1}`, "parent_id would create a cycle", 400, false, false},
		{"TwoNodeCycle_400_NoWrites", "PUT", `{"parent_id":2}`, "parent_id would create a cycle", 400, true, false},
		{"CreateIntoCycle_400_NoWrites", "POST", `{"prefix":"10.0.0.0/24","parent_id":2}`, "parent_id would create a cycle", 400, true, false},
		{"CreateMissingParent_400_NoWrites", "POST", `{"prefix":"10.0.0.0/24","parent_id":99}`, "parent_id not found", 400, false, false},
		{"PreflightListError", "PUT", `{"parent_id":2}`, "database error", 500, false, true},
		{"CreatePreflightListError", "POST", `{"prefix":"10.0.0.0/24","parent_id":2}`, "database error", 500, false, true},
		{"LegalParent_PublishesAndAudits", "PUT", `{"parent_id":2}`, "", 200, false, false},
		{"CreateLegalParent_PublishesAndAudits", "POST", `{"prefix":"10.0.0.0/24","parent_id":2}`, "", 201, false, false},
		{"UpdateMissingParent_400_NoWrites", "PUT", `{"parent_id":99}`, "parent_id not found", 400, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dao13aAPIBase()
			if tc.badCycle {
				s.rows[1].ParentID = intPtr(1)
				if tc.method == "POST" {
					s.rows[0].ParentID = intPtr(2)
				}
			}
			s.listErr = tc.listErr
			before := append([]store.WatchPrefix(nil), s.rows...)
			rec := dao13aAPIRequest(t, s, true, tc.method, tc.body)
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.message) {
				t.Errorf("status=%d body=%s; want %d %q", rec.Code, rec.Body.String(), tc.status, tc.message)
			}
			if tc.status >= 400 {
				if s.creates != 0 || s.updates != 0 || s.publishes != 0 || s.audits != 0 || !reflect.DeepEqual(before, s.rows) {
					t.Errorf("rejected request mutated state: creates=%d updates=%d publishes=%d audits=%d rows=%+v", s.creates, s.updates, s.publishes, s.audits, s.rows)
				}
			} else if s.creates+s.updates != 1 || s.publishes != 1 || s.audits != 1 {
				t.Errorf("positive control: writes=%d publishes=%d audits=%d", s.creates+s.updates, s.publishes, s.audits)
			}
		})
	}
	t.Run("OmittedParent_NoPreflightList", func(t *testing.T) {
		for _, tc := range []struct {
			name, method, body string
			status             int
		}{
			{"Omitted", "PUT", `{"enabled":true}`, 200},
			{"Null", "PUT", `{"parent_id":null}`, 200},
			{"NameOnly", "PUT", `{"name":"renamed"}`, 200},
			{"CreateOmitted", "POST", `{"prefix":"10.0.0.0/24"}`, 201},
			{"CreateNull", "POST", `{"prefix":"10.0.0.0/24","parent_id":null}`, 201},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := dao13aAPIBase()
				s.listErr = true
				rec := dao13aAPIRequest(t, s, false, tc.method, tc.body)
				if rec.Code != tc.status || s.lists != 0 || s.updates+s.creates != 1 {
					t.Fatalf("status=%d lists=%d writes=%d body=%s", rec.Code, s.lists, s.updates+s.creates, rec.Body.String())
				}
			})
		}
	})
}
