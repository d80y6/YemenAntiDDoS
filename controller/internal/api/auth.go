package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// authMiddleware validates either API key or JWT token.
func authMiddleware(apiKey, jwtSecret string, st store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check API key first
		if key := c.GetHeader("X-API-Key"); key != "" {
			if subtle.ConstantTimeCompare([]byte(key), []byte(apiKey)) == 1 {
				c.Set("auth_type", "apikey")
				c.Set("role", "admin")
				c.Next()
				return
			}
			errResponse(c, http.StatusUnauthorized, "invalid API key")
			c.Abort()
			return
		}

		// Check JWT
		auth := c.GetHeader("Authorization")
		if auth == "" {
			errResponse(c, http.StatusUnauthorized, "missing authentication")
			c.Abort()
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		claims := &jwtClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
			return []byte(jwtSecret), nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
		if err != nil || !token.Valid {
			errResponse(c, http.StatusUnauthorized, "invalid token")
			c.Abort()
			return
		}

		user, err := st.Users().Get(c, claims.UserID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				errResponse(c, http.StatusUnauthorized, "invalid token")
				c.Abort()
				return
			}
			errResponse(c, http.StatusServiceUnavailable, "authentication backend unavailable")
			c.Abort()
			return
		}
		if user == nil {
			errResponse(c, http.StatusUnauthorized, "invalid token")
			c.Abort()
			return
		}
		if !user.Enabled {
			errResponse(c, http.StatusUnauthorized, "invalid token")
			c.Abort()
			return
		}
		if user.UpdatedAt.UnixMicro() != claims.Rev {
			errResponse(c, http.StatusUnauthorized, "invalid token")
			c.Abort()
			return
		}
		c.Set("auth_type", "jwt")
		c.Set("user_id", user.ID)
		c.Set("username", user.Username)
		c.Set("role", user.Role)
		c.Next()
	}
}

func requireAdminForWrites() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet {
			c.Next()
			return
		}
		if c.GetString("role") != "admin" {
			errResponse(c, http.StatusForbidden, "admin role required")
			c.Abort()
			return
		}
		c.Next()
	}
}

type jwtClaims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Rev      int64  `json:"rev"`
	jwt.RegisteredClaims
}

func generateJWT(secret string, u *store.User) (string, error) {
	claims := jwtClaims{
		UserID:   u.ID,
		Username: u.Username,
		Role:     u.Role,
		Rev:      u.UpdatedAt.UnixMicro(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

var bcryptCompare = bcrypt.CompareHashAndPassword

func checkPassword(hash, password string) bool {
	return bcryptCompare([]byte(hash), []byte(password)) == nil
}

var dummyLoginOnce sync.Once
var dummyLoginPasswordHash string

func dummyLoginHash() string {
	dummyLoginOnce.Do(func() {
		hash, err := hashPassword("xsight-login-dummy-password")
		if err != nil {
			panic(fmt.Errorf("create dummy login hash: %w", err))
		}
		dummyLoginPasswordHash = hash
	})
	return dummyLoginPasswordHash
}

const (
	loginWindow         = 15 * time.Minute
	loginMaxPerUserAddr = 5
	loginMaxPerAddr     = 20
	loginMaxKeys        = 10000
)

type loginBucketKey struct {
	user, addr  string
	addressOnly bool
}

type loginBucket struct {
	start time.Time
	count int
}

type loginLimiter struct {
	mu              sync.Mutex
	buckets         map[loginBucketKey]loginBucket
	now             func() time.Time
	maxKeys         int
	nextCapacityLog time.Time
}

func newLoginLimiter(now func() time.Time, maxKeys int) *loginLimiter {
	return &loginLimiter{buckets: make(map[loginBucketKey]loginBucket), now: now, maxKeys: maxKeys}
}

func (l *loginLimiter) reserve(user, addr string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for key, bucket := range l.buckets {
		if !now.Before(bucket.start.Add(loginWindow)) {
			delete(l.buckets, key)
		}
	}
	userKey := loginBucketKey{user: user, addr: addr}
	addrKey := loginBucketKey{addr: addr, addressOnly: true}
	userBucket, hasUser := l.buckets[userKey]
	addrBucket, hasAddr := l.buckets[addrKey]
	if hasUser && userBucket.count >= loginMaxPerUserAddr {
		return false, userBucket.start.Add(loginWindow).Sub(now)
	}
	if hasAddr && addrBucket.count >= loginMaxPerAddr {
		return false, addrBucket.start.Add(loginWindow).Sub(now)
	}
	needed := 0
	if !hasUser {
		needed++
	}
	if !hasAddr {
		needed++
	}
	if len(l.buckets)+needed > l.maxKeys {
		if !now.Before(l.nextCapacityLog) {
			log.Printf("WARN api: login limiter capacity reached; rejecting new keys")
			l.nextCapacityLog = now.Add(loginWindow)
		}
		return false, loginWindow
	}
	if !hasUser {
		userBucket.start = now
	}
	if !hasAddr {
		addrBucket.start = now
	}
	userBucket.count++
	addrBucket.count++
	l.buckets[userKey] = userBucket
	l.buckets[addrKey] = addrBucket
	return true, 0
}

func (l *loginLimiter) succeeded(user, addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, loginBucketKey{user: user, addr: addr})
	key := loginBucketKey{addr: addr, addressOnly: true}
	if bucket, ok := l.buckets[key]; ok && bucket.count > 0 {
		bucket.count--
		l.buckets[key] = bucket
	}
}

// loginHandler authenticates a user and returns a JWT.
func loginHandler(deps Dependencies, lim *loginLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, "username and password required")
			return
		}
		addr, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			addr = c.Request.RemoteAddr
		}
		if allowed, retryAfter := lim.reserve(req.Username, addr); !allowed {
			c.Header("Retry-After", strconv.FormatInt(int64((retryAfter+time.Second-1)/time.Second), 10))
			errResponse(c, http.StatusTooManyRequests, "too many login attempts")
			return
		}
		user, err := deps.Store.Users().GetByUsername(c, req.Username)
		hash := dummyLoginHash()
		if err == nil && user != nil {
			hash = user.Password
		}
		validPassword := checkPassword(hash, req.Password)
		if err != nil {
			log.Printf("ERROR api: login user lookup: %v", err)
		}
		if err != nil || user == nil || !user.Enabled || !validPassword {
			errResponse(c, http.StatusUnauthorized, "invalid credentials")
			return
		}
		lim.succeeded(req.Username, addr)
		token, err := generateJWT(deps.JWTSecret, user)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, "token generation failed")
			return
		}
		ok(c, gin.H{"token": token, "user": gin.H{
			"id": user.ID, "username": user.Username, "role": user.Role,
		}})
	}
}

// EnsureInitialAdmin creates the first administrator or rotates legacy default passwords.
func EnsureInitialAdmin(ctx context.Context, users store.UserRepo, initialPassword string) error {
	all, err := users.List(ctx)
	if err != nil {
		return fmt.Errorf("list users for initial admin: %w", err)
	}
	if len(all) == 0 {
		if initialPassword == "" {
			return errors.New("no users exist; set auth.initial_admin_password to create the first admin")
		}
		hash, err := hashPassword(initialPassword)
		if err != nil {
			return fmt.Errorf("hash initial admin password: %w", err)
		}
		if _, err := users.Create(ctx, &store.User{Username: "admin", Password: hash, Role: "admin", Enabled: true}); err != nil {
			return fmt.Errorf("create initial admin: %w", err)
		}
		log.Printf("created initial admin user %q from auth.initial_admin_password", "admin")
		return nil
	}
	rotated := false
	for _, u := range all {
		if u.Role != "admin" || !checkPassword(u.Password, "admin") {
			continue
		}
		if initialPassword == "" {
			return fmt.Errorf("admin user %q still uses the default password; set auth.initial_admin_password", u.Username)
		}
		hash, err := hashPassword(initialPassword)
		if err != nil {
			return fmt.Errorf("hash initial admin password: %w", err)
		}
		u.Password = hash
		if err := users.Update(ctx, &u); err != nil {
			return fmt.Errorf("rotate default password for admin %q: %w", u.Username, err)
		}
		rotated = true
		log.Printf("WARN api: rotated default password for admin user %q", u.Username)
	}
	if initialPassword != "" && !rotated {
		log.Printf("INFO api: auth.initial_admin_password is set but unused; it can be removed")
	}
	return nil
}
