package api

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type dao12cLoginStore struct {
	store.Store
	user *store.User
}
type dao12cUsers struct {
	store.UserRepo
	user *store.User
}

func (s dao12cLoginStore) Users() store.UserRepo { return dao12cUsers{user: s.user} }
func (r dao12cUsers) GetByUsername(context.Context, string) (*store.User, error) {
	return r.user, nil
}
func (r dao12cUsers) Get(context.Context, int) (*store.User, error) {
	return r.user, nil
}
func dao12cAuthRequest(configKey, requestKey, token string, st store.Store) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/", authMiddleware(configKey, "dao12c-secret", st), func(c *gin.Context) { c.Status(204) })
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", requestKey)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}
func TestDao12c_G2(t *testing.T) {
	for _, tc := range []struct {
		name, configured, supplied string
		want                       int
	}{
		{"G2a.KeyOK/ASCII", "api-key", "api-key", 204},
		{"G2a.KeyOK/NonASCII", "\xc3\xa9-key", "\xc3\xa9-key", 204},
		{"G2b.KeyBad/Wrong", "api-key", "bad-key", 401},
		{"G2b.KeyBad/Longer", "api-key", "api-key-more", 401},
		{"G2b.KeyBad/Shorter", "api-key", "api", 401},
		{"G2b.KeyBad/NonASCII", "\xc3\xa9-key", "\xc3\xa8-key", 401},
		{"G2b.KeyBad/Empty", "api-key", "", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := dao12cAuthRequest(tc.configured, tc.supplied, "", nil)
			dao11cEqual(t, rec.Code, tc.want)
			if tc.supplied == "" && !strings.Contains(rec.Body.String(), "missing authentication") {
				t.Errorf("empty key did not take JWT path: %s", rec.Body.String())
			}
		})
	}
	t.Run("G2c.HS256", func(t *testing.T) {
		password, err := hashPassword("dao12c-password")
		if err != nil {
			t.Fatal(err)
		}
		s := dao12cLoginStore{user: &store.User{ID: 1, Username: "operator", Password: password, Role: "admin", Enabled: true}}
		req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"operator","password":"dao12c-password"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		NewRouter(Dependencies{Store: s, JWTSecret: "dao12c-secret"}).ServeHTTP(rec, req)
		var body struct{ Token string }
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if rec.Code != 200 || body.Token == "" {
			t.Fatalf("login status=%d body=%s", rec.Code, rec.Body.String())
		}
		dao11cEqual(t, dao12cAuthRequest("", "", body.Token, s).Code, 204)
	})
	for _, method := range []jwt.SigningMethod{jwt.SigningMethodHS512, jwt.SigningMethodHS384, jwt.SigningMethodNone} {
		name, key := "G2d."+method.Alg(), any([]byte("dao12c-secret"))
		if method == jwt.SigningMethodNone {
			name, key = "G2e.None", jwt.UnsafeAllowNoneSignatureType
		}
		t.Run(name, func(t *testing.T) {
			signed, err := jwt.NewWithClaims(method, &jwtClaims{UserID: 1}).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			dao11cEqual(t, dao12cAuthRequest("", "", signed, nil).Code, 401)
		})
	}
}

func dao12cExpr(n ast.Node) string {
	var b bytes.Buffer
	_ = format.Node(&b, token.NewFileSet(), n)
	return b.String()
}
func dao12cCompare(e ast.Expr) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok || dao12cExpr(c.Fun) != "subtle.ConstantTimeCompare" || len(c.Args) != 2 {
		return false
	}
	a, b := dao12cExpr(c.Args[0]), dao12cExpr(c.Args[1])
	return a == "[]byte(key)" && b == "[]byte(apiKey)" || a == "[]byte(apiKey)" && b == "[]byte(key)"
}
func TestDao12c_G2f(t *testing.T) {
	path := "auth.go"
	if source := os.Getenv("DAO12C_STATIC_AUTH"); source != "" {
		path = source
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if f, ok := decl.(*ast.FuncDecl); ok && f.Name.Name == "authMiddleware" {
			body = f.Body
		}
	}
	if body == nil {
		t.Fatal("authMiddleware missing")
	}
	var condition ast.Expr
	plain := false
	ast.Inspect(body, func(n ast.Node) bool {
		if b, ok := n.(*ast.BinaryExpr); ok && (b.Op == token.EQL || b.Op == token.NEQ) {
			a, c := dao12cExpr(ast.Unparen(b.X)), dao12cExpr(ast.Unparen(b.Y))
			plain = plain || a == "key" && c == "apiKey" || a == "apiKey" && c == "key"
		}
		if outer, ok := n.(*ast.IfStmt); ok && outer.Init != nil && dao12cExpr(outer.Init) == `key := c.GetHeader("X-API-Key")` {
			for _, statement := range outer.Body.List {
				if inner, ok := statement.(*ast.IfStmt); ok {
					condition = inner.Cond
					break
				}
			}
		}
		return true
	})
	comparator, polarity := false, false
	if condition != nil {
		ast.Inspect(condition, func(n ast.Node) bool {
			if e, ok := n.(ast.Expr); ok && dao12cCompare(e) {
				comparator = true
			}
			if b, ok := n.(*ast.BinaryExpr); ok && b.Op == token.EQL {
				polarity = polarity || dao12cCompare(b.X) && dao12cExpr(b.Y) == "1" || dao12cCompare(b.Y) && dao12cExpr(b.X) == "1"
			}
			return true
		})
	}
	t.Run("Comparator", func(t *testing.T) {
		if !comparator || plain {
			t.Errorf("API-key condition constant-time call=%v, plain key/apiKey comparison=%v", comparator, plain)
		}
	})
	t.Run("Polarity", func(t *testing.T) {
		if !polarity {
			t.Error("API-key condition must compare ConstantTimeCompare result == 1")
		}
	})
}
