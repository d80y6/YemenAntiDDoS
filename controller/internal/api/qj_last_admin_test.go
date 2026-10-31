package api

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type qjUsers struct {
	store.UserRepo
	getErr, writeErr error
	writes           int
}

func (r *qjUsers) Get(context.Context, int) (*store.User, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	return &store.User{ID: 7, Username: "qj-fixture", Password: "fixture-hash", Role: "admin", Enabled: true}, nil
}

func (r *qjUsers) Update(context.Context, *store.User) error {
	r.writes++
	return r.writeErr
}

func (r *qjUsers) Delete(context.Context, int) error {
	r.writes++
	return r.writeErr
}

type qjHandlerStore struct {
	store.Store
	users qjUsers
	audit dao13bAudit
}

func (s *qjHandlerStore) Users() store.UserRepo        { return &s.users }
func (s *qjHandlerStore) AuditLog() store.AuditLogRepo { return &s.audit }

func TestQJLastAdminHandler(t *testing.T) {
	for _, method := range []string{"PUT", "DELETE"} {
		for _, tc := range []struct {
			name   string
			err    error
			status int
			audits int
			body   string
		}{
			{"Sentinel", store.ErrLastAdmin, 409, 0, `{"error":"at least one enabled admin is required"}`},
			{"Wrapped", fmt.Errorf("wrapped: %w", store.ErrLastAdmin), 409, 0, `{"error":"at least one enabled admin is required"}`},
			{"Success", nil, 200, 1, `{"ok":true}`},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				s := &qjHandlerStore{users: qjUsers{writeErr: tc.err}}
				// dao13bRequest uses NewRecorder + ServeHTTP; no listener is opened.
				w := dao13bRequest(dao13bRouter(s), method, "/api/users/7", `{"role":"viewer","enabled":true}`, "apikey", "", nil)
				if w.Code != tc.status || w.Body.String() != tc.body {
					t.Errorf("status/body=%d %s want=%d %s", w.Code, w.Body, tc.status, tc.body)
				}
				if len(s.audit.rows) != tc.audits {
					t.Errorf("Audit.Create calls=%d want=%d", len(s.audit.rows), tc.audits)
				}
				if s.users.writes != 1 {
					t.Errorf("user writes=%d want=1", s.users.writes)
				}
				t.Logf("status=%d body=%s Audit.Create=%d writes=%d", w.Code, w.Body, len(s.audit.rows), s.users.writes)
			})
		}
	}
	t.Run("PUT/GetFailure", func(t *testing.T) {
		s := &qjHandlerStore{users: qjUsers{getErr: errors.New("fixture get failed"), writeErr: store.ErrLastAdmin}}
		w := dao13bRequest(dao13bRouter(s), "PUT", "/api/users/7", `{"role":"viewer","enabled":true}`, "apikey", "", nil)
		if w.Code != 404 || w.Body.String() != `{"error":"user not found"}` {
			t.Errorf("status/body=%d %s want=404 user not found", w.Code, w.Body)
		}
		if s.users.writes != 0 || len(s.audit.rows) != 0 {
			t.Errorf("writes=%d audits=%d want=0/0", s.users.writes, len(s.audit.rows))
		}
		t.Logf("status=%d body=%s Audit.Create=%d writes=%d", w.Code, w.Body, len(s.audit.rows), s.users.writes)
	})
}
