package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const dao13bKey = "dao13b-api-key"
const dao13bSecret = "dao13b-jwt-secret"
const dao13bPassword = "dao13b-password"

var dao13bRevision = time.Date(2026, 1, 1, 0, 0, 0, 100000, time.UTC)
var dao13bHashOnce sync.Once
var dao13bHash string

func dao13bPasswordHash(t *testing.T) string {
	t.Helper()
	dao13bHashOnce.Do(func() {
		hash, err := bcrypt.GenerateFromPassword([]byte(dao13bPassword), bcrypt.DefaultCost)
		if err != nil {
			t.Fatal(err)
		}
		dao13bHash = string(hash)
	})
	return dao13bHash
}

type dao13bUsers struct {
	store.UserRepo
	mu                                                                     sync.Mutex
	rows                                                                   map[int]store.User
	immutable                                                              bool
	getErr, loginErr, listErr, writeErr                                    error
	nilGet                                                                 bool
	getCalls, loginCalls, listCalls, createCalls, updateCalls, deleteCalls int
	created                                                                []store.User
}

func dao13bUserFixture(t *testing.T) *dao13bUsers {
	t.Helper()
	r := &dao13bUsers{rows: map[int]store.User{}}
	for i, role := range []string{"admin", "viewer", "operator", "superuser"} {
		r.rows[i+1] = store.User{ID: i + 1, Username: role, Role: role, Enabled: true, Password: dao13bPasswordHash(t), UpdatedAt: dao13bRevision}
	}
	return r
}

func (r *dao13bUsers) Get(_ context.Context, id int) (*store.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.getCalls++
	if r.getErr != nil {
		return nil, r.getErr
	}
	if r.nilGet {
		return nil, nil
	}
	u, ok := r.rows[id]
	if !ok {
		return nil, fmt.Errorf("user %d: %w", id, pgx.ErrNoRows)
	}
	return &u, nil
}
func (r *dao13bUsers) GetByUsername(_ context.Context, name string) (*store.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loginCalls++
	if r.loginErr != nil {
		return nil, r.loginErr
	}
	for _, row := range r.rows {
		if row.Username == name {
			u := row
			return &u, nil
		}
	}
	return nil, nil
}
func (r *dao13bUsers) List(context.Context) ([]store.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listCalls++
	if r.listErr != nil {
		return nil, r.listErr
	}
	var result []store.User
	for _, u := range r.rows {
		result = append(result, u)
	}
	return result, nil
}
func (r *dao13bUsers) Create(_ context.Context, u *store.User) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.createCalls++
	if r.writeErr != nil {
		return 0, r.writeErr
	}
	r.created = append(r.created, *u)
	id := len(r.rows) + 1
	if !r.immutable {
		v := *u
		v.ID = id
		v.UpdatedAt = dao13bRevision
		r.rows[id] = v
	}
	return id, nil
}
func (r *dao13bUsers) Update(_ context.Context, u *store.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updateCalls++
	if r.writeErr != nil {
		return r.writeErr
	}
	if !r.immutable {
		v := *u
		v.UpdatedAt = v.UpdatedAt.Add(time.Microsecond)
		r.rows[v.ID] = v
	}
	return nil
}
func (r *dao13bUsers) Delete(_ context.Context, id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleteCalls++
	if r.writeErr != nil {
		return r.writeErr
	}
	if !r.immutable {
		delete(r.rows, id)
	}
	return nil
}

type dao13bAuthStore struct {
	store.Store
	users *dao13bUsers
}

func (s *dao13bAuthStore) Users() store.UserRepo { return s.users }

type dao13bAudit struct {
	store.AuditLogRepo
	rows []store.AuditLog
	err  error
}

func (r *dao13bAudit) Create(_ context.Context, a *store.AuditLog) error {
	r.rows = append(r.rows, dao11cCopy(*a))
	return r.err
}

type dao13bShells struct {
	store.ShellConnectorRepo
	calls int
}

func (r *dao13bShells) Create(context.Context, *store.ShellConnector) (int, error) {
	r.calls++
	return 1, nil
}

type dao13bCountStore struct {
	*dao13bAuthStore
	audit  dao13bAudit
	shells dao13bShells
}

func (s *dao13bCountStore) AuditLog() store.AuditLogRepo              { return &s.audit }
func (s *dao13bCountStore) ShellConnectors() store.ShellConnectorRepo { return &s.shells }

func dao13bRouter(st store.Store) *gin.Engine {
	return NewRouter(Dependencies{Store: st, APIKey: dao13bKey, JWTSecret: dao13bSecret})
}
func dao13bSign(t *testing.T, u store.User, issued, expires time.Time, omitRev bool) string {
	t.Helper()
	claims := jwt.MapClaims{"user_id": u.ID, "username": u.Username, "role": u.Role, "iat": issued.Unix(), "exp": expires.Unix()}
	if !omitRev {
		claims["rev"] = u.UpdatedAt.UnixMicro()
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(dao13bSecret))
	if err != nil {
		t.Fatal(err)
	}
	return token
}
func dao13bToken(t *testing.T, u store.User) string {
	return dao13bSign(t, u, time.Now(), time.Now().Add(time.Hour), false)
}
func dao13bRequest(r http.Handler, method, path, body, identity, addr string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	switch identity {
	case "apikey":
		req.Header.Set("X-API-Key", dao13bKey)
	case "badkey":
		req.Header.Set("X-API-Key", "wrong")
	case "":
	default:
		req.Header.Set("Authorization", "Bearer "+identity)
	}
	if addr == "" {
		addr = "192.0.2.10:1234"
	}
	req.RemoteAddr = addr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
func dao13bLogin(r http.Handler, name, password, addr string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"username": name, "password": password})
	return dao13bRequest(r, "POST", "/api/login", string(body), "", addr, nil)
}
func dao13bWantStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body)
	}
}

func TestDao13b_T(t *testing.T) {
	old := gin.DefaultErrorWriter
	gin.DefaultErrorWriter = io.Discard
	t.Cleanup(func() { gin.DefaultErrorWriter = old })
	base := dao13bRouter(&dao13bAuthStore{users: dao13bUserFixture(t)})
	routes := base.Routes()
	writes := 0
	login, metrics := false, false
	for _, route := range routes {
		if route.Method == "POST" && route.Path == "/api/login" {
			login = true
			continue
		}
		if route.Method == "GET" && route.Path == "/metrics" {
			metrics = true
			continue
		}
		if !strings.HasPrefix(route.Path, "/api/") {
			t.Fatalf("unexpected route %s %s", route.Method, route.Path)
		}
		if route.Method != "GET" {
			writes++
		}
	}
	t.Logf("registered routes=%d authenticated writes=%d", len(routes), writes)
	if !login || !metrics || writes < 50 {
		t.Fatalf("enumeration incomplete: login=%v metrics=%v writes=%d", login, metrics, writes)
	}
	for _, route := range routes {
		if route.Path == "/api/login" || route.Path == "/metrics" {
			continue
		}
		for _, identity := range []string{"none", "badkey", "viewer", "operator", "superuser", "admin", "apikey"} {
			t.Run(route.Method+route.Path+"/"+identity, func(t *testing.T) {
				users := dao13bUserFixture(t)
				users.immutable = true
				r := dao13bRouter(&dao13bAuthStore{users: users})
				credential := identity
				if identity == "none" {
					credential = ""
				}
				for _, u := range users.rows {
					if u.Role == identity {
						credential = dao13bToken(t, u)
					}
				}
				parts := strings.Split(route.Path, "/")
				for i, p := range parts {
					if strings.HasPrefix(p, ":") {
						parts[i] = "1"
					}
				}
				w := dao13bRequest(r, route.Method, strings.Join(parts, "/"), "{}", credential, "", nil)
				switch {
				case identity == "none" || identity == "badkey":
					dao13bWantStatus(t, w, 401)
				case identity != "admin" && identity != "apikey" && route.Method != "GET":
					dao13bWantStatus(t, w, 403)
					if w.Body.String() != `{"error":"admin role required"}` {
						t.Errorf("authorization body=%q", w.Body.String())
					}
				default:
					if w.Code == 401 || w.Code == 403 {
						t.Errorf("identity rejected: status=%d body=%s", w.Code, w.Body)
					}
				}
			})
		}
	}
	t.Run("Public", func(t *testing.T) {
		r := dao13bRouter(&dao13bAuthStore{users: dao13bUserFixture(t)})
		dao13bWantStatus(t, dao13bRequest(r, "GET", "/metrics", "", "", "", nil), 200)
		dao13bWantStatus(t, dao13bLogin(r, "viewer", dao13bPassword, ""), 200)
	})
	t.Run("Counts", func(t *testing.T) {
		for _, target := range []struct{ name, path, body string }{
			{"User", "/api/users", `{"username":"t-new","password":"t-pass-1","role":"admin"}`},
			{"Shell", "/api/settings/shell-connectors", `{"name":"t-shell","command":"/bin/true"}`},
		} {
			for _, identity := range []string{"viewer", "admin", "apikey"} {
				t.Run(target.name+"/"+identity, func(t *testing.T) {
					u := dao13bUserFixture(t)
					u.immutable = true
					s := &dao13bCountStore{dao13bAuthStore: &dao13bAuthStore{users: u}}
					credential := identity
					if identity == "viewer" {
						credential = dao13bToken(t, u.rows[2])
					}
					if identity == "admin" {
						credential = dao13bToken(t, u.rows[1])
					}
					w := dao13bRequest(dao13bRouter(s), "POST", target.path, target.body, credential, "", nil)
					wantStatus, wantWrites := 201, 1
					if identity == "viewer" {
						wantStatus, wantWrites = 403, 0
					}
					dao13bWantStatus(t, w, wantStatus)
					if identity == "viewer" && w.Body.String() != `{"error":"admin role required"}` {
						t.Errorf("exact denial body=%q", w.Body.String())
					}
					calls := u.createCalls
					if target.name == "Shell" {
						calls = s.shells.calls
					}
					if calls != wantWrites {
						t.Errorf("Create calls=%d want=%d", calls, wantWrites)
					}
					if target.name == "User" && len(s.audit.rows) != wantWrites {
						t.Errorf("Audit.Create calls=%d want=%d", len(s.audit.rows), wantWrites)
					}
				})
			}
		}
	})
}

func TestDao13b_U(t *testing.T) {
	for _, tc := range []struct {
		role, method string
		want         int
	}{
		{"viewer", "PATCH", 403}, {"viewer", "HEAD", 403}, {"viewer", "OPTIONS", 403}, {"viewer", "PURGE", 403},
		{"admin", "PATCH", 204}, {"", "POST", 403}, {"viewer", "GET", 204},
	} {
		t.Run(tc.role+"/"+tc.method, func(t *testing.T) {
			r := gin.New()
			calls := 0
			r.Handle(tc.method, "/", func(c *gin.Context) {
				if tc.role != "" {
					c.Set("role", tc.role)
				}
			}, requireAdminForWrites(), func(c *gin.Context) { calls++; c.Status(204) })
			w := dao13bRequest(r, tc.method, "/", "", "", "", nil)
			dao13bWantStatus(t, w, tc.want)
			wantCalls := 0
			if tc.want == 204 {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Errorf("handler calls=%d want=%d", calls, wantCalls)
			}
		})
	}
}

func dao13bProbe(t *testing.T, users *dao13bUsers, token string, status int) {
	t.Helper()
	users.listCalls = 0
	w := dao13bRequest(dao13bRouter(&dao13bAuthStore{users: users}), "GET", "/api/users", "", token, "", nil)
	dao13bWantStatus(t, w, status)
	if status == 200 {
		if users.listCalls != 1 {
			t.Errorf("List calls=%d want=1", users.listCalls)
		}
		return
	}
	body := `{"error":"invalid token"}`
	if status == 503 {
		body = `{"error":"authentication backend unavailable"}`
	}
	if users.listCalls != 0 {
		t.Errorf("denied request reached List %d times", users.listCalls)
	}
	if w.Body.String() != body {
		t.Errorf("exact denial body=%q want=%q", w.Body.String(), body)
	}
}

func TestDao13b_D(t *testing.T) {
	t.Run("Untouched", func(t *testing.T) { u := dao13bUserFixture(t); dao13bProbe(t, u, dao13bToken(t, u.rows[2]), 200) })
	t.Run("FutureRev", func(t *testing.T) {
		u := dao13bUserFixture(t)
		claims := u.rows[2]
		claims.UpdatedAt = claims.UpdatedAt.Add(time.Microsecond)
		dao13bProbe(t, u, dao13bToken(t, claims), 401)
	})
	t.Run("Disabled", func(t *testing.T) {
		u := dao13bUserFixture(t)
		token := dao13bToken(t, u.rows[2])
		row := u.rows[2]
		row.Enabled = false
		u.rows[2] = row
		dao13bProbe(t, u, token, 401)
	})
	t.Run("GetErrors", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			err     error
			nilUser bool
			status  int
		}{
			{"ErrNoRows", fmt.Errorf("user 2: %w", pgx.ErrNoRows), false, 401},
			{"DBDown", errors.New("db down"), false, 503}, {"NilUser", nil, true, 401},
		} {
			t.Run(tc.name, func(t *testing.T) {
				u := dao13bUserFixture(t)
				u.getErr = tc.err
				u.nilGet = tc.nilUser
				dao13bProbe(t, u, dao13bToken(t, u.rows[2]), tc.status)
			})
		}
	})
	t.Run("PasswordChanged", func(t *testing.T) {
		u := dao13bUserFixture(t)
		token := dao13bToken(t, u.rows[2])
		row := u.rows[2]
		row.UpdatedAt = row.UpdatedAt.Add(time.Microsecond)
		u.rows[2] = row
		dao13bProbe(t, u, token, 401)
	})
	t.Run("Demoted", func(t *testing.T) {
		u := dao13bUserFixture(t)
		token := dao13bToken(t, u.rows[1])
		row := u.rows[1]
		row.Role = "viewer"
		row.UpdatedAt = row.UpdatedAt.Add(time.Microsecond)
		u.rows[1] = row
		dao13bProbe(t, u, token, 401)
		r := dao13bRouter(&dao13bAuthStore{users: u})
		w := dao13bLogin(r, row.Username, dao13bPassword, "")
		dao13bWantStatus(t, w, 200)
		var body struct{ Token string }
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		dao13bProbe(t, u, body.Token, 200)
		dao13bWantStatus(t, dao13bRequest(r, "POST", "/api/users", "{}", body.Token, "", nil), 403)
	})
	t.Run("SameSecond", func(t *testing.T) {
		u := dao13bUserFixture(t)
		a := u.rows[2]
		b := a
		b.UpdatedAt = b.UpdatedAt.Add(100 * time.Microsecond)
		u.rows[2] = b
		issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		expires := time.Now().Add(time.Hour)
		t.Run("A", func(t *testing.T) { dao13bProbe(t, u, dao13bSign(t, a, issued, expires, false), 401) })
		t.Run("B", func(t *testing.T) { dao13bProbe(t, u, dao13bSign(t, b, issued, expires, false), 200) })
	})
	t.Run("RoleFromDB", func(t *testing.T) {
		u := dao13bUserFixture(t)
		claims := u.rows[2]
		claims.Role = "admin"
		dao13bWantStatus(t, dao13bRequest(dao13bRouter(&dao13bAuthStore{users: u}), "POST", "/api/users", "{}", dao13bToken(t, claims), "", nil), 403)
	})
	t.Run("IdentityFromDB", func(t *testing.T) {
		u := dao13bUserFixture(t)
		row := u.rows[2]
		row.Username = "alice"
		u.rows[2] = row
		claims := row
		claims.Username = "spoof"
		claims.Role = "admin"
		r := gin.New()
		r.GET("/", authMiddleware(dao13bKey, dao13bSecret, &dao13bAuthStore{users: u}), func(c *gin.Context) {
			c.JSON(200, gin.H{"id": c.GetInt("user_id"), "username": c.GetString("username"), "role": c.GetString("role")})
		})
		w := dao13bRequest(r, "GET", "/", "", dao13bToken(t, claims), "", nil)
		dao13bWantStatus(t, w, 200)
		if w.Body.String() != `{"id":2,"role":"viewer","username":"alice"}` {
			t.Errorf("identity=%s", w.Body)
		}
	})
	t.Run("OldFormat", func(t *testing.T) {
		u := dao13bUserFixture(t)
		dao13bProbe(t, u, dao13bSign(t, u.rows[2], time.Now(), time.Now().Add(time.Hour), true), 401)
	})
	t.Run("Expired", func(t *testing.T) {
		u := dao13bUserFixture(t)
		dao13bProbe(t, u, dao13bSign(t, u.rows[2], time.Now().Add(-time.Hour), time.Now().Add(-time.Minute), false), 401)
	})
}

func TestDao13b_R0Fixed(t *testing.T) {
	t.Run("a", func(t *testing.T) {
		u := dao13bUserFixture(t)
		s := &dao13bCountStore{dao13bAuthStore: &dao13bAuthStore{users: u}}
		w := dao13bRequest(dao13bRouter(s), "POST", "/api/users", `{"username":"r0-evil","password":"r0-pass-1","role":"admin"}`, dao13bToken(t, u.rows[2]), "", nil)
		dao13bWantStatus(t, w, 403)
		if u.createCalls != 0 {
			t.Errorf("Create calls=%d", u.createCalls)
		}
	})
	t.Run("b", func(t *testing.T) {
		u := dao13bUserFixture(t)
		token := dao13bToken(t, u.rows[2])
		row := u.rows[2]
		row.Enabled = false
		u.rows[2] = row
		dao13bProbe(t, u, token, 401)
	})
	t.Run("c", func(t *testing.T) {
		u := dao13bUserFixture(t)
		r := dao13bRouter(&dao13bAuthStore{users: u})
		unknown := dao13bLogin(r, "unknown", "wrong", "192.0.2.1:1234")
		row := u.rows[2]
		row.Enabled = false
		u.rows[2] = row
		disabled := dao13bLogin(r, "viewer", "wrong", "192.0.2.1:1234")
		dao13bWantStatus(t, unknown, 401)
		dao13bWantStatus(t, disabled, 401)
		if unknown.Body.String() != disabled.Body.String() {
			t.Errorf("failure bodies differ: %s / %s", unknown.Body, disabled.Body)
		}
		row.Enabled = true
		u.rows[2] = row
		for i := 1; i <= 6; i++ {
			want := 401
			if i == 6 {
				want = 429
			}
			dao13bWantStatus(t, dao13bLogin(r, "viewer", "wrong", "192.0.2.2:1234"), want)
		}
	})
	t.Run("d", func(t *testing.T) {
		b, err := os.ReadFile("../../main.go")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `[]byte("admin")`) {
			t.Error("default-password seed remains")
		}
	})
	t.Run("e", func(t *testing.T) {
		s := &dao13bCountStore{dao13bAuthStore: &dao13bAuthStore{users: dao13bUserFixture(t)}}
		w := dao13bRequest(dao13bRouter(s), "POST", "/api/users", `{"username":"r0-evil","password":"r0-pass-1","role":"admin"}`, "apikey", "", nil)
		dao13bWantStatus(t, w, 201)
		if len(s.audit.rows) != 1 {
			t.Errorf("Audit.Create calls=%d", len(s.audit.rows))
		}
	})
}

func dao13bLimiterEngine(t *testing.T, u *dao13bUsers, lim *loginLimiter) *gin.Engine {
	t.Helper()
	r := gin.New()
	r.POST("/api/login", loginHandler(Dependencies{Store: &dao13bAuthStore{users: u}, JWTSecret: dao13bSecret}, lim))
	return r
}

func TestDao13b_L(t *testing.T) {
	t.Run("L1", func(t *testing.T) {
		for i, tc := range []struct {
			name, user, password string
			disabled, dbError    bool
		}{
			{"Unknown", "unknown", "wrong", false, false}, {"DisabledCorrect", "viewer", dao13bPassword, true, false},
			{"DisabledWrong", "viewer", "wrong", true, false}, {"EnabledWrong", "viewer", "wrong", false, false},
			{"DBError", "viewer", "wrong", false, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				u := dao13bUserFixture(t)
				row := u.rows[2]
				row.Enabled = !tc.disabled
				u.rows[2] = row
				if tc.dbError {
					u.loginErr = errors.New("db down")
				}
				w := dao13bLogin(dao13bRouter(&dao13bAuthStore{users: u}), tc.user, tc.password, fmt.Sprintf("192.0.2.%d:1234", i+1))
				dao13bWantStatus(t, w, 401)
				if w.Body.String() != `{"error":"invalid credentials"}` {
					t.Errorf("failure body=%q", w.Body.String())
				}
			})
		}
	})
	t.Run("L2", func(t *testing.T) {
		u := dao13bUserFixture(t)
		r := dao13bRouter(&dao13bAuthStore{users: u})
		for i := 0; i < 5; i++ {
			dao13bWantStatus(t, dao13bLogin(r, "viewer", "wrong", ""), 401)
		}
		for _, password := range []string{"wrong", dao13bPassword} {
			w := dao13bLogin(r, "viewer", password, "")
			dao13bWantStatus(t, w, 429)
			retry, err := strconv.Atoi(w.Header().Get("Retry-After"))
			if err != nil || retry <= 0 {
				t.Errorf("Retry-After=%q", w.Header().Get("Retry-After"))
			}
		}
		if u.loginCalls != 5 {
			t.Errorf("GetByUsername calls=%d want=5", u.loginCalls)
		}
	})
	t.Run("L3", func(t *testing.T) {
		for _, name := range []string{"UserAddrFull", "AddrFull", "AddrFullNewUser"} {
			t.Run(name, func(t *testing.T) {
				t0 := dao13bRevision
				now := t0
				lim := newLoginLimiter(func() time.Time { return now }, 100)
				user := "u"
				n := 5
				if name != "UserAddrFull" {
					n = 20
				}
				for i := 0; i < n; i++ {
					if name != "UserAddrFull" {
						user = fmt.Sprintf("u%d", i)
					}
					if ok, _ := lim.reserve(user, "a"); !ok {
						t.Fatal("fill rejected")
					}
				}
				before := map[loginBucketKey]loginBucket{}
				for k, v := range lim.buckets {
					before[k] = v
				}
				user = "u"
				if name == "AddrFull" {
					user = "u1"
				}
				if name == "AddrFullNewUser" {
					user = "u21"
				}
				now = t0.Add(time.Minute)
				if ok, _ := lim.reserve(user, "a"); ok {
					t.Error("full bucket accepted")
				}
				if !reflect.DeepEqual(lim.buckets, before) {
					t.Errorf("rejection changed buckets: before=%v after=%v", before, lim.buckets)
				}
				for k, b := range lim.buckets {
					if !b.start.Equal(t0) {
						t.Errorf("bucket %v start=%v want=%v", k, b.start, t0)
					}
				}
				now = t0.Add(loginWindow)
				if ok, _ := lim.reserve(user, "a"); !ok {
					t.Error("window did not expire at t0+15m")
				}
			})
		}
	})
	t.Run("L4", func(t *testing.T) {
		r := dao13bRouter(&dao13bAuthStore{users: dao13bUserFixture(t)})
		for i := 0; i < 4; i++ {
			dao13bWantStatus(t, dao13bLogin(r, "viewer", "wrong", ""), 401)
		}
		dao13bWantStatus(t, dao13bLogin(r, "viewer", dao13bPassword, ""), 200)
		for i := 0; i < 4; i++ {
			dao13bWantStatus(t, dao13bLogin(r, "viewer", "wrong", ""), 401)
		}
	})
	t.Run("L4b", func(t *testing.T) {
		lim := newLoginLimiter(time.Now, loginMaxKeys)
		r := dao13bLimiterEngine(t, dao13bUserFixture(t), lim)
		for i := 0; i < 25; i++ {
			dao13bWantStatus(t, dao13bLogin(r, "viewer", dao13bPassword, ""), 200)
		}
		if n := lim.buckets[loginBucketKey{addr: "192.0.2.10", addressOnly: true}].count; n != 0 {
			t.Errorf("address count=%d want=0", n)
		}
	})
	t.Run("L5", func(t *testing.T) {
		t.Run("AddressIsolation", func(t *testing.T) {
			r := dao13bRouter(&dao13bAuthStore{users: dao13bUserFixture(t)})
			for i := 0; i < 5; i++ {
				dao13bWantStatus(t, dao13bLogin(r, "viewer", "wrong", "192.0.2.1:1"), 401)
			}
			dao13bWantStatus(t, dao13bLogin(r, "viewer", "wrong", "192.0.2.2:1"), 401)
		})
		t.Run("AddressBucket", func(t *testing.T) {
			r := dao13bRouter(&dao13bAuthStore{users: dao13bUserFixture(t)})
			for i := 0; i < 20; i++ {
				dao13bWantStatus(t, dao13bLogin(r, fmt.Sprintf("unknown%d", i), "wrong", ""), 401)
			}
			dao13bWantStatus(t, dao13bLogin(r, "unknown21", "wrong", ""), 429)
		})
	})
	t.Run("L6", func(t *testing.T) {
		r := dao13bRouter(&dao13bAuthStore{users: dao13bUserFixture(t)})
		for i := 0; i < 6; i++ {
			headers := map[string]string{"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", i+1), "X-Real-IP": fmt.Sprintf("203.0.113.%d", i+1)}
			w := dao13bRequest(r, "POST", "/api/login", `{"username":"viewer","password":"wrong"}`, "", "192.0.2.1:1", headers)
			want := 401
			if i == 5 {
				want = 429
			}
			dao13bWantStatus(t, w, want)
		}
	})
	t.Run("L7", func(t *testing.T) {
		u := dao13bUserFixture(t)
		r := dao13bRouter(&dao13bAuthStore{users: u})
		start := make(chan struct{})
		codes := make(chan int, 20)
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; codes <- dao13bLogin(r, "viewer", "wrong", "").Code }()
		}
		close(start)
		wg.Wait()
		close(codes)
		counts := map[int]int{}
		for code := range codes {
			counts[code]++
		}
		if u.loginCalls != 5 || counts[401] != 5 || counts[429] != 15 {
			t.Errorf("concurrent calls=%d statuses=%v want 5 lookups, 5x401, 15x429", u.loginCalls, counts)
		}
	})
	t.Run("L8", func(t *testing.T) {
		now := dao13bRevision
		lim := newLoginLimiter(func() time.Time { return now }, 2)
		if ok, _ := lim.reserve("u", "a"); !ok {
			t.Fatal("initial request rejected")
		}
		if ok, _ := lim.reserve("v", "b"); ok {
			t.Error("new keys accepted at capacity")
		}
		if ok, _ := lim.reserve("u", "a"); !ok {
			t.Error("existing keys rejected at capacity")
		}
		now = now.Add(loginWindow)
		if ok, _ := lim.reserve("v", "b"); !ok {
			t.Error("expired capacity not recovered")
		}
	})
	t.Run("L8b", func(t *testing.T) {
		lim := newLoginLimiter(func() time.Time { return dao13bRevision }, 3)
		lim.reserve("u", "a")
		before := len(lim.buckets)
		ok, retry := lim.reserve("v", "b")
		if ok || retry != 900*time.Second || len(lim.buckets) != before {
			t.Errorf("atomic capacity: ok=%v retry=%v size=%d want=%d", ok, retry, len(lim.buckets), before)
		}
	})
	t.Run("L9", func(t *testing.T) {
		a := dao13bRouter(&dao13bAuthStore{users: dao13bUserFixture(t)})
		for i := 0; i < 5; i++ {
			dao13bWantStatus(t, dao13bLogin(a, "viewer", "wrong", ""), 401)
		}
		dao13bWantStatus(t, dao13bLogin(a, "viewer", "wrong", ""), 429)
		b := dao13bRouter(&dao13bAuthStore{users: dao13bUserFixture(t)})
		dao13bWantStatus(t, dao13bLogin(b, "viewer", "wrong", ""), 401)
	})
	t.Run("L10", func(t *testing.T) {
		u := dao13bUserFixture(t)
		r := dao13bRouter(&dao13bAuthStore{users: u})
		for i := 0; i < 6; i++ {
			dao13bWantStatus(t, dao13bRequest(r, "POST", "/api/login", "{", "", "", nil), 400)
		}
		dao13bWantStatus(t, dao13bLogin(r, "viewer", dao13bPassword, ""), 200)
		if u.loginCalls != 1 {
			t.Errorf("invalid JSON reached repository: calls=%d", u.loginCalls)
		}
	})
	t.Run("L11", func(t *testing.T) {
		for _, tc := range []struct {
			name, user, password string
			disabled, dbError    bool
			status               int
		}{
			{"Unknown", "unknown", "wrong", false, false, 401}, {"DisabledCorrect", "viewer", dao13bPassword, true, false, 401},
			{"DisabledWrong", "viewer", "wrong", true, false, 401}, {"EnabledWrong", "viewer", "wrong", false, false, 401},
			{"DBError", "viewer", "wrong", false, true, 401}, {"Success", "viewer", dao13bPassword, false, false, 200},
		} {
			t.Run(tc.name, func(t *testing.T) {
				u := dao13bUserFixture(t)
				row := u.rows[2]
				row.Enabled = !tc.disabled
				u.rows[2] = row
				if tc.dbError {
					u.loginErr = errors.New("db down")
				}
				var hashes []string
				old := bcryptCompare
				bcryptCompare = func(hash, password []byte) error { hashes = append(hashes, string(hash)); return old(hash, password) }
				t.Cleanup(func() { bcryptCompare = old })
				w := dao13bLogin(dao13bRouter(&dao13bAuthStore{users: u}), tc.user, tc.password, "")
				dao13bWantStatus(t, w, tc.status)
				if len(hashes) != 1 {
					t.Fatalf("bcrypt comparisons=%d want=1", len(hashes))
				}
				if tc.user == "unknown" || tc.dbError {
					cost, err := bcrypt.Cost([]byte(hashes[0]))
					if hashes[0] != dummyLoginHash() || err != nil || cost != bcrypt.DefaultCost {
						t.Errorf("dummy hash mismatch or cost: cost=%d err=%v", cost, err)
					}
				}
			})
		}
		t.Run("Rejected", func(t *testing.T) {
			lim := newLoginLimiter(time.Now, loginMaxKeys)
			for i := 0; i < 5; i++ {
				lim.reserve("viewer", "192.0.2.10")
			}
			calls := 0
			old := bcryptCompare
			bcryptCompare = func(hash, password []byte) error { calls++; return old(hash, password) }
			t.Cleanup(func() { bcryptCompare = old })
			dao13bWantStatus(t, dao13bLogin(dao13bLimiterEngine(t, dao13bUserFixture(t), lim), "viewer", dao13bPassword, ""), 429)
			if calls != 0 {
				t.Errorf("rejected request compared password %d times", calls)
			}
		})
	})
	t.Run("L11b", func(t *testing.T) {
		hash := dummyLoginHash()
		cost, err := bcrypt.Cost([]byte(hash))
		if err != nil || cost != bcrypt.DefaultCost {
			t.Fatalf("dummy cost=%d err=%v", cost, err)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("x")); !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			t.Errorf("dummy comparison error=%v", err)
		}
		if hash != dummyLoginHash() {
			t.Error("dummy hash changed")
		}
	})
}
