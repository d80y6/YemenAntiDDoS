package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type dao8Store struct {
	store.Store
	prefixes *dao8Prefixes
}

func (s *dao8Store) Prefixes() store.PrefixRepo { return s.prefixes }

type dao8Prefixes struct {
	store.PrefixRepo
	mu     sync.Mutex
	row    store.WatchPrefix
	writes int
}

func (r *dao8Prefixes) Get(context.Context, int) (*store.WatchPrefix, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row := r.row
	return &row, nil
}
func (r *dao8Prefixes) Create(_ context.Context, p *store.WatchPrefix) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.row = *p
	r.row.ID = 1
	r.writes++
	return 1, nil
}
func (r *dao8Prefixes) Update(_ context.Context, p *store.WatchPrefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.row = *p
	r.writes++
	return nil
}
func (r *dao8Prefixes) snapshot() (store.WatchPrefix, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.row, r.writes
}

func dao8PrefixAPI(t *testing.T, values []string, reject bool, methods ...string) {
	t.Helper()
	if len(methods) == 0 {
		methods = []string{"POST", "PUT"}
	}
	for _, method := range methods {
		for _, prefix := range values {
			t.Run(method+"/"+prefix, func(t *testing.T) {
				repo := &dao8Prefixes{row: store.WatchPrefix{ID: 1, Prefix: "198.51.100.0/24", Enabled: true}}
				router := NewRouter(Dependencies{Store: &dao8Store{prefixes: repo}, APIKey: "dao8-test"})
				body, err := json.Marshal(map[string]string{"prefix": prefix})
				if err != nil {
					t.Fatal(err)
				}
				path := "/api/prefixes"
				want := 201
				if method == "PUT" {
					path += "/1"
					want = 200
				}
				if reject {
					want = 400
				}
				req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-API-Key", "dao8-test")
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != want {
					t.Errorf("%s %q status = %d, want %d; body=%s", method, prefix, rec.Code, want, rec.Body.String())
				}
				row, writes := repo.snapshot()
				if reject {
					if writes != 0 || row.Prefix != "198.51.100.0/24" {
						t.Errorf("rejected prefix persisted: row=%+v writes=%d", row, writes)
					}
				} else if writes != 1 || row.Prefix != prefix {
					t.Errorf("accepted prefix not persisted: row=%+v writes=%d", row, writes)
				}
			})
		}
	}
}
func TestDao8_C5_RejectMappedPrefix(t *testing.T) {
	dao8PrefixAPI(t, []string{"::ffff:192.0.2.0/120", "::ffff:192.0.2.0/80", "::ffff:c000:200/120",
		"::ffff:192.0.2.0/0120", "::ffff:192.0.2.0/080", "::ffff:192.0.2.1"}, true)
}
func TestDao8_C5b_AcceptNativePrefix(t *testing.T) {
	dao8PrefixAPI(t, []string{"192.0.2.0/24", "2001:db8::/32", "::/80"}, false)
	dao8PrefixAPI(t, []string{"2001:db8::1"}, false, "POST")
}
