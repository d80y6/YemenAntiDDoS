package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/configpub"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func TestDao13b_S(t *testing.T) {
	defaultHash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, username, role, password, initial string
		empty, enabled, wantError               bool
		creates, updates                        int
	}{
		{"S1", "admin", "admin", "", "initial-pass", true, true, false, 1, 0},
		{"S2", "", "", "", "", true, false, true, 0, 0},
		{"S3", "admin", "admin", string(defaultHash), "initial-pass", false, true, false, 0, 1},
		{"S4", "root", "admin", string(defaultHash), "initial-pass", false, true, false, 0, 1},
		{"S5", "admin", "admin", dao13bPasswordHash(t), "initial-pass", false, true, false, 0, 0},
		{"S6", "root", "admin", string(defaultHash), "", false, true, true, 0, 0},
		{"S7", "viewer", "viewer", string(defaultHash), "initial-pass", false, true, false, 0, 0},
		{"S8", "root", "admin", string(defaultHash), "initial-pass", false, false, false, 0, 1},
		{"S8b", "root", "admin", string(defaultHash), "", false, false, true, 0, 0},
		{"S9/Viewer", "viewer", "viewer", dao13bPasswordHash(t), "", false, true, false, 0, 0},
		{"S9/Operator", "operator", "operator", dao13bPasswordHash(t), "", false, true, false, 0, 0},
		{"S9/DisabledAdmin", "root", "admin", dao13bPasswordHash(t), "", false, false, false, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &dao13bUsers{rows: map[int]store.User{}}
			if !tc.empty {
				r.rows[1] = store.User{ID: 1, Username: tc.username, Role: tc.role, Password: tc.password, Enabled: tc.enabled, UpdatedAt: dao13bRevision}
			}
			err := EnsureInitialAdmin(context.Background(), r, tc.initial)
			if (err != nil) != tc.wantError {
				t.Fatalf("EnsureInitialAdmin error=%v wantError=%v", err, tc.wantError)
			}
			if r.createCalls != tc.creates || r.updateCalls != tc.updates {
				t.Fatalf("Create=%d Update=%d want=%d/%d", r.createCalls, r.updateCalls, tc.creates, tc.updates)
			}
			if tc.wantError && tc.username != "" && (!strings.Contains(err.Error(), tc.username) || !strings.Contains(err.Error(), "auth.initial_admin_password")) {
				t.Errorf("error lacks account/config: %v", err)
			}
			if tc.creates+tc.updates > 0 {
				u := r.rows[1]
				if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(tc.initial)) != nil || bcrypt.CompareHashAndPassword([]byte(u.Password), []byte("admin")) == nil {
					t.Error("configured password was not installed")
				}
				if u.Username != tc.username || u.Role != "admin" || u.Enabled != tc.enabled {
					t.Errorf("identity changed: %+v", u)
				}
			} else if !tc.empty && r.rows[1].Password != tc.password {
				t.Error("unmatched password changed")
			}
			if tc.name == "S3" {
				t.Run("Idempotent", func(t *testing.T) {
					r.updateCalls = 0
					if err := EnsureInitialAdmin(context.Background(), r, tc.initial); err != nil {
						t.Fatal(err)
					}
					if r.updateCalls != 0 {
						t.Errorf("second startup updates=%d", r.updateCalls)
					}
				})
			}
		})
	}
	t.Run("S10", func(t *testing.T) {
		r := &dao13bUsers{listErr: errors.New("list failed")}
		if err := EnsureInitialAdmin(context.Background(), r, "initial-pass"); err == nil {
			t.Error("List error was ignored")
		}
	})
	t.Run("MultipleAdmins", func(t *testing.T) {
		const initialPassword = "multiple-admin-pass"
		before := map[int]store.User{
			2:  {ID: 2, Username: "first", Role: "admin", Enabled: true, Password: string(defaultHash), UpdatedAt: dao13bRevision},
			9:  {ID: 9, Username: "renamed", Role: "admin", Enabled: false, Password: string(defaultHash), UpdatedAt: dao13bRevision},
			23: {ID: 23, Username: "changed", Role: "admin", Enabled: true, Password: dao13bPasswordHash(t), UpdatedAt: dao13bRevision},
			27: {ID: 27, Username: "reader", Role: "viewer", Enabled: true, Password: string(defaultHash), UpdatedAt: dao13bRevision},
		}
		r := &dao13bInitialUsers{dao13bUsers: &dao13bUsers{rows: make(map[int]store.User)}}
		for id, row := range before {
			r.rows[id] = row
		}
		if err := EnsureInitialAdmin(context.Background(), r, initialPassword); err != nil {
			t.Fatal(err)
		}
		t.Run("UpdateIDs", func(t *testing.T) {
			ids := append([]int(nil), r.updatedIDs...)
			sort.Ints(ids)
			if !reflect.DeepEqual(ids, []int{2, 9}) {
				t.Errorf("Update IDs=%v want exactly [2 9]", ids)
			}
			if r.createCalls != 0 || r.updateCalls != 2 || r.deleteCalls != 0 {
				t.Errorf("Create/Update/Delete=%d/%d/%d want 0/2/0", r.createCalls, r.updateCalls, r.deleteCalls)
			}
		})
		for _, id := range []int{2, 9, 23, 27} {
			t.Run(fmt.Sprintf("Row%d", id), func(t *testing.T) {
				old := before[id]
				got, ok := r.rows[id]
				if !ok {
					t.Fatal("user row disappeared")
				}
				if got.ID != old.ID || got.Username != old.Username || got.Role != old.Role || got.Enabled != old.Enabled {
					t.Errorf("identity changed for user %d", id)
				}
				if id == 2 || id == 9 {
					if err := bcrypt.CompareHashAndPassword([]byte(got.Password), []byte(initialPassword)); err != nil {
						t.Errorf("configured password missing for user %d: %v", id, err)
					}
					if err := bcrypt.CompareHashAndPassword([]byte(got.Password), []byte("admin")); err != bcrypt.ErrMismatchedHashAndPassword {
						t.Errorf("default password remains or hash is invalid for user %d: %v", id, err)
					}
				} else if !reflect.DeepEqual(got, old) {
					t.Errorf("unmatched user %d changed", id)
				}
			})
		}
		t.Run("Idempotent", func(t *testing.T) {
			firstRows := make(map[int]store.User)
			for id, row := range r.rows {
				firstRows[id] = row
			}
			r.updatedIDs = nil
			r.createCalls, r.updateCalls, r.deleteCalls = 0, 0, 0
			if err := EnsureInitialAdmin(context.Background(), r, initialPassword); err != nil {
				t.Fatal(err)
			}
			if len(r.updatedIDs) != 0 || r.createCalls != 0 || r.updateCalls != 0 || r.deleteCalls != 0 {
				t.Errorf("second startup Update IDs=%v Create/Update/Delete=%d/%d/%d want no writes", r.updatedIDs, r.createCalls, r.updateCalls, r.deleteCalls)
			}
			if !reflect.DeepEqual(r.rows, firstRows) {
				t.Error("second startup changed user rows")
			}
		})
	})
}

type dao13bInitialUsers struct {
	*dao13bUsers
	updatedIDs []int
}

func (r *dao13bInitialUsers) Update(ctx context.Context, u *store.User) error {
	r.updatedIDs = append(r.updatedIDs, u.ID)
	return r.dao13bUsers.Update(ctx, u)
}

type dao13bNodes struct {
	store.NodeRepo
	rows                                map[string]store.Node
	getErr, writeErr                    error
	creates, updates, deletes, versions int
}

func (r *dao13bNodes) List(context.Context) ([]store.Node, error) {
	var out []store.Node
	for _, row := range r.rows {
		out = append(out, dao11cCopy(row))
	}
	return out, nil
}
func (r *dao13bNodes) Get(_ context.Context, id string) (*store.Node, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	u, ok := r.rows[id]
	if !ok {
		return nil, errors.New("node missing")
	}
	u = dao11cCopy(u)
	return &u, nil
}
func (r *dao13bNodes) Create(_ context.Context, n *store.Node) error {
	r.creates++
	if r.writeErr != nil {
		return r.writeErr
	}
	r.rows[n.ID] = dao11cCopy(*n)
	return nil
}
func (r *dao13bNodes) Update(_ context.Context, n *store.Node) error {
	r.updates++
	if r.writeErr != nil {
		return r.writeErr
	}
	r.rows[n.ID] = dao11cCopy(*n)
	return nil
}
func (r *dao13bNodes) Delete(_ context.Context, id string) error {
	r.deletes++
	if r.writeErr != nil {
		return r.writeErr
	}
	delete(r.rows, id)
	return nil
}
func (r *dao13bNodes) UpdateDeliveryVersionCurrent(_ context.Context, id string, v int64) error {
	r.versions++
	n := r.rows[id]
	n.DeliveryVersionCurrent = v
	r.rows[id] = n
	return nil
}

type dao13bListeners struct {
	store.FlowListenerRepo
	listErr, deleteErr error
	deletes            int
	rows               []store.FlowListener
}

func (r *dao13bListeners) List(context.Context, string) ([]store.FlowListener, error) {
	return r.rows, r.listErr
}
func (r *dao13bListeners) Delete(context.Context, int) error { r.deletes++; return r.deleteErr }

type dao13bAuditStore struct {
	*dao11cStore
	users     *dao13bUsers
	nodes     *dao13bNodes
	listeners dao13bListeners
	audit     dao13bAudit
}

func (s *dao13bAuditStore) Users() store.UserRepo                 { return s.users }
func (s *dao13bAuditStore) Nodes() store.NodeRepo                 { return s.nodes }
func (s *dao13bAuditStore) FlowListeners() store.FlowListenerRepo { return &s.listeners }
func (s *dao13bAuditStore) AuditLog() store.AuditLogRepo          { return &s.audit }
func dao13bAuditFixture(t *testing.T) *dao13bAuditStore {
	u := dao13bUserFixture(t)
	u.rows[5] = store.User{ID: 5, Username: "target", Role: "admin", Enabled: true, Password: dao13bPasswordHash(t), UpdatedAt: dao13bRevision}
	return &dao13bAuditStore{dao11cStore: dao11cFixture(), users: u, nodes: &dao13bNodes{rows: map[string]store.Node{
		"n-pub":  {ID: "n-pub", Enabled: true, Mode: "xdp"},
		"n-crud": {ID: "n-crud", Enabled: true, Mode: "xdp", APIKey: "private-node-key", Description: "before"},
	}}}
}

type dao13bAuditCase struct {
	name, method, path, body, entity, id, action string
	status                                       int
}

var dao13bAuditCases = []dao13bAuditCase{
	{"CreateUser", "POST", "/api/users", `{"username":"audit-new","password":"private-password","role":"viewer"}`, "user", "6", "create", 201},
	{"UpdateUser", "PUT", "/api/users/5", `{"role":"viewer","password":"private-password"}`, "user", "5", "update", 200},
	{"DeleteUser", "DELETE", "/api/users/5", "", "user", "5", "delete", 200},
	{"CreateNode", "POST", "/api/nodes", `{"id":"n-crud","api_key":"private-node-key","description":"new"}`, "node", "n-crud", "create", 201},
	{"UpdateNode", "PUT", "/api/nodes/n-crud", `{"description":"after"}`, "node", "n-crud", "update", 200},
	{"DeleteNode", "DELETE", "/api/nodes/n-crud", "", "node", "n-crud", "delete", 200},
}

func dao13bDiff(t *testing.T, a store.AuditLog) map[string]map[string]any {
	t.Helper()
	var diff map[string]map[string]any
	if err := json.Unmarshal(a.Diff, &diff); err != nil {
		t.Fatal(err)
	}
	return diff
}
func dao13bAuditCheck(t *testing.T, s *dao13bAuditStore, tc dao13bAuditCase, jwtIdentity bool) {
	t.Helper()
	if len(s.audit.rows) != 1 {
		t.Fatalf("Audit.Create calls=%d want=1", len(s.audit.rows))
	}
	a := s.audit.rows[0]
	if a.EntityType != tc.entity || a.EntityID != tc.id || a.Action != tc.action || a.DeliveryVersion != nil {
		t.Errorf("audit identity/version=%+v", a)
	}
	if jwtIdentity && (a.UserID == nil || *a.UserID != 1) {
		t.Errorf("JWT audit user=%v want=1", a.UserID)
	}
	if !jwtIdentity && a.UserID != nil {
		t.Errorf("API-key audit user=%v want=nil", a.UserID)
	}
	for _, secret := range []string{"private-password", "private-node-key", "$2a$", "$2b$"} {
		if strings.Contains(string(a.Diff), secret) {
			t.Errorf("audit leaked %q: %s", secret, a.Diff)
		}
	}
	if tc.name == "UpdateUser" {
		diff := dao13bDiff(t, a)
		if diff["new"]["password_changed"] != true || diff["old"]["role"] != "admin" || diff["new"]["role"] != "viewer" {
			t.Errorf("update diff=%s", a.Diff)
		}
	}
	if tc.name == "UpdateNode" {
		diff := dao13bDiff(t, a)
		if diff["old"]["description"] != "before" || diff["new"]["description"] != "after" {
			t.Errorf("node update diff=%s", a.Diff)
		}
	}
}

func TestDao13b_A(t *testing.T) {
	for _, tc := range dao13bAuditCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, identity := range []string{"JWT", "APIKey"} {
				t.Run(identity, func(t *testing.T) {
					s := dao13bAuditFixture(t)
					credential := "apikey"
					if identity == "JWT" {
						credential = dao13bToken(t, s.users.rows[1])
					}
					w := dao13bRequest(dao13bRouter(s), tc.method, tc.path, tc.body, credential, "", nil)
					dao13bWantStatus(t, w, tc.status)
					dao13bAuditCheck(t, s, tc, identity == "JWT")
				})
			}
			t.Run("WriteFailure", func(t *testing.T) {
				s := dao13bAuditFixture(t)
				s.users.writeErr = errors.New("write failed")
				s.nodes.writeErr = errors.New("write failed")
				w := dao13bRequest(dao13bRouter(s), tc.method, tc.path, tc.body, "apikey", "", nil)
				dao13bWantStatus(t, w, 500)
				if len(s.audit.rows) != 0 {
					t.Error("failed write audited")
				}
			})
			t.Run("Viewer", func(t *testing.T) {
				s := dao13bAuditFixture(t)
				w := dao13bRequest(dao13bRouter(s), tc.method, tc.path, tc.body, dao13bToken(t, s.users.rows[2]), "", nil)
				dao13bWantStatus(t, w, 403)
				if len(s.audit.rows) != 0 {
					t.Error("denied write audited")
				}
			})
			t.Run("AuditFailure", func(t *testing.T) {
				control := dao13bAuditFixture(t)
				a := dao13bRequest(dao13bRouter(control), tc.method, tc.path, tc.body, "apikey", "", nil)
				s := dao13bAuditFixture(t)
				s.audit.err = errors.New("audit failed")
				b := dao13bRequest(dao13bRouter(s), tc.method, tc.path, tc.body, "apikey", "", nil)
				if a.Code != tc.status || b.Code != a.Code || b.Body.String() != a.Body.String() {
					t.Errorf("audit failure changed response: control=%d %s failed=%d %s", a.Code, a.Body, b.Code, b.Body)
				}
				if len(s.audit.rows) != 1 {
					t.Errorf("audit attempt count=%d", len(s.audit.rows))
				}
			})
		})
	}
	t.Run("BadBody", func(t *testing.T) {
		for _, path := range []string{"/api/users", "/api/nodes"} {
			s := dao13bAuditFixture(t)
			w := dao13bRequest(dao13bRouter(s), "POST", path, "{}", "apikey", "", nil)
			dao13bWantStatus(t, w, 400)
			if len(s.audit.rows) != 0 {
				t.Error("bad request audited")
			}
		}
	})
	t.Run("PasswordWhitespace", func(t *testing.T) {
		for _, password := range []string{"   ", " new-pass-1 "} {
			t.Run(fmt.Sprintf("%q", password), func(t *testing.T) {
				s := dao13bAuditFixture(t)
				old := s.users.rows[5].Password
				body, _ := json.Marshal(map[string]string{"password": password})
				w := dao13bRequest(dao13bRouter(s), "PUT", "/api/users/5", string(body), "apikey", "", nil)
				dao13bWantStatus(t, w, 200)
				if len(s.audit.rows) != 1 {
					t.Fatalf("audits=%d", len(s.audit.rows))
				}
				changed := strings.TrimSpace(password) != ""
				if got := dao13bDiff(t, s.audit.rows[0])["new"]["password_changed"]; got != changed {
					t.Errorf("password_changed=%v want=%v", got, changed)
				}
				if (s.users.rows[5].Password != old) != changed {
					t.Error("hash change disagrees with actual password branch")
				}
				if changed && bcrypt.CompareHashAndPassword([]byte(s.users.rows[5].Password), []byte("new-pass-1")) != nil {
					t.Error("new password not installed")
				}
			})
		}
	})
	t.Run("SelfDelete", func(t *testing.T) {
		s := dao13bAuditFixture(t)
		w := dao13bRequest(dao13bRouter(s), "DELETE", "/api/users/1", "", dao13bToken(t, s.users.rows[1]), "", nil)
		dao13bWantStatus(t, w, 200)
		if len(s.audit.rows) != 1 || s.audit.rows[0].UserID != nil {
			t.Errorf("self-delete audit=%+v", s.audit.rows)
		}
	})
	t.Run("UserDeleteGetFails", func(t *testing.T) {
		s := dao13bAuditFixture(t)
		s.users.getErr = errors.New("lookup failed")
		w := dao13bRequest(dao13bRouter(s), "DELETE", "/api/users/5", "", "apikey", "", nil)
		dao13bWantStatus(t, w, 200)
		if s.users.deleteCalls != 1 || len(s.audit.rows) != 1 {
			t.Fatalf("delete=%d audit=%d", s.users.deleteCalls, len(s.audit.rows))
		}
		if string(s.audit.rows[0].Diff) != `{"new":null,"old":{"id":5}}` {
			t.Errorf("fallback diff=%s", s.audit.rows[0].Diff)
		}
	})
	t.Run("NodeDeleteGetFails", func(t *testing.T) {
		s := dao13bAuditFixture(t)
		s.nodes.getErr = errors.New("lookup failed")
		w := dao13bRequest(dao13bRouter(s), "DELETE", "/api/nodes/n-crud", "", "apikey", "", nil)
		dao13bWantStatus(t, w, 200)
		if s.nodes.deletes != 1 || len(s.audit.rows) != 1 {
			t.Fatalf("delete=%d audit=%d", s.nodes.deletes, len(s.audit.rows))
		}
		if string(s.audit.rows[0].Diff) != `{"new":null,"old":{"id":"n-crud"}}` {
			t.Errorf("fallback diff=%s", s.audit.rows[0].Diff)
		}
	})
	t.Run("NodeCascadeFailure", func(t *testing.T) {
		s := dao13bAuditFixture(t)
		s.listeners.rows = []store.FlowListener{{ID: 1}}
		s.nodes.writeErr = errors.New("node delete failed")
		w := dao13bRequest(dao13bRouter(s), "DELETE", "/api/nodes/n-crud", "", "apikey", "", nil)
		dao13bWantStatus(t, w, 500)
		if s.listeners.deletes != 1 || len(s.audit.rows) != 0 {
			t.Errorf("listener deletes=%d audit=%d", s.listeners.deletes, len(s.audit.rows))
		}
	})
	t.Run("NoPublish", func(t *testing.T) {
		s := dao13bAuditFixture(t)
		delete(s.nodes.rows, "n-crud")
		connected := 0
		publisher := configpub.New(s, nil, func() []string { connected++; return nil })
		r := NewRouter(Dependencies{Store: s, APIKey: dao13bKey, JWTSecret: dao13bSecret, ConfigPub: publisher})
		for _, tc := range dao13bAuditCases {
			path := tc.path
			if tc.entity == "user" && tc.action != "create" {
				path = "/api/users/6"
			}
			dao13bWantStatus(t, dao13bRequest(r, tc.method, path, tc.body, "apikey", "", nil), tc.status)
		}
		versioned := func() int {
			n := 0
			for _, a := range s.audit.rows {
				if a.DeliveryVersion != nil {
					n++
				}
			}
			return n
		}
		if connected != 0 || s.nodes.versions != 0 || versioned() != 0 || len(s.audit.rows) != 6 {
			t.Errorf("CRUD published: connected=%d versions=%d versioned audits=%d all audits=%d", connected, s.nodes.versions, versioned(), len(s.audit.rows))
		}
		if n, ok := s.nodes.rows["n-pub"]; !ok || !n.Enabled {
			t.Fatal("positive-control node was removed or disabled")
		}
		dao13bWantStatus(t, dao13bRequest(r, "POST", "/api/settings/shell-connectors", `{"name":"publish-control","command":"/bin/true"}`, "apikey", "", nil), 201)
		if connected < 1 || s.nodes.versions < 1 || versioned() < 1 {
			t.Fatalf("STOP: publish positive control invisible: connected=%d versions=%d versioned audits=%d", connected, s.nodes.versions, versioned())
		}
	})
}
