package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type d2APIStore struct {
	store.Store
	live     int
	queryErr bool
	deleted  bool
}
type d2APIRules struct {
	store.XDropActiveRuleRepo
	s *d2APIStore
}
type d2APIConns struct {
	store.XDropConnectorRepo
	s *d2APIStore
}
type d2APITargets struct{ store.XDropTargetRepo }

func (s *d2APIStore) XDropActiveRules() store.XDropActiveRuleRepo       { return d2APIRules{s: s} }
func (s *d2APIStore) XDropConnectors() store.XDropConnectorRepo         { return d2APIConns{s: s} }
func (s *d2APIStore) XDropTargets() store.XDropTargetRepo               { return d2APITargets{} }
func (d2APITargets) CountByConnector(context.Context, int) (int, error) { return 0, nil }

// 拟增接口；HEAD 可编译，测试不会依赖替身自判 409。
func (r d2APIRules) CountLiveByConnector(context.Context, int) (int, error) {
	if r.s.queryErr {
		return 0, errors.New("private-database-detail")
	}
	return r.s.live, nil
}
func (r d2APIConns) Get(context.Context, int) (*store.XDropConnector, error) { return nil, nil }
func (r d2APIConns) Delete(context.Context, int) error                       { r.s.deleted = true; return nil }
func d2APICall(s *d2APIStore) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.DELETE("/connectors/:id", deleteXDropConnector(Dependencies{Store: s}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/connectors/7", nil))
	return w
}
func TestD2A_B14_DeleteConnector409(t *testing.T) {
	s := &d2APIStore{live: 1}
	w := d2APICall(s)
	if w.Code != 409 || s.deleted {
		t.Fatalf("status=%d deleted=%v", w.Code, s.deleted)
	}
	if !strings.Contains(w.Body.String(), "xDrop connector still has active rules") {
		t.Fatalf("fixed message missing: %s", w.Body.String())
	}
}
func TestD2A_B15_DeleteQueryFailureClosed(t *testing.T) {
	s := &d2APIStore{queryErr: true}
	w := d2APICall(s)
	if w.Code != 500 || s.deleted {
		t.Fatalf("status=%d deleted=%v", w.Code, s.deleted)
	}
	if strings.Contains(w.Body.String(), "private-database-detail") {
		t.Fatal("internal detail leaked")
	}
	if !strings.Contains(w.Body.String(), "failed to check xDrop connector usage") {
		t.Fatalf("fixed query failure message missing: %s", w.Body.String())
	}
}
func TestD2A_G05_EmptyConnectorDelete(t *testing.T) {
	s := &d2APIStore{}
	w := d2APICall(s)
	if w.Code != 200 || !s.deleted {
		t.Fatalf("status=%d deleted=%v", w.Code, s.deleted)
	}
}
