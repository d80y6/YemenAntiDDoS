package api

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/gin-gonic/gin"
	dto "github.com/prometheus/client_model/go"
)

type dao11jOrphanRepo struct {
	store.BGPAnnouncementRepo
	mu               sync.Mutex
	row              store.BGPAnnouncement
	entered, release chan struct{}
	claims           atomic.Int64
}

func (r *dao11jOrphanRepo) Get(context.Context, int) (*store.BGPAnnouncement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.row
	return &a, nil
}
func (r *dao11jOrphanRepo) ListByStatus(_ context.Context, status string) ([]store.BGPAnnouncement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.row.Status == status {
		return []store.BGPAnnouncement{r.row}, nil
	}
	return nil, nil
}
func (r *dao11jOrphanRepo) ForceWithdraw(context.Context, int) ([]store.BGPAnnouncementAttack, int, error) {
	r.mu.Lock()
	r.row.Gen++
	r.row.Status = "withdrawing"
	gen := r.row.Gen
	r.mu.Unlock()
	// Bubble-local barrier after the committed transition, before vtysh.
	close(r.entered)
	<-r.release
	return nil, gen, nil
}
func (r *dao11jOrphanRepo) ClaimWithdrawing(_ context.Context, id, gen int) (int, bool, error) {
	r.claims.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.row.ID != id || r.row.Gen != gen || r.row.Status != "withdrawing" {
		return 0, false, nil
	}
	r.row.Gen++
	return r.row.Gen, true, nil
}
func (r *dao11jOrphanRepo) MarkWithdrawn(_ context.Context, id, gen int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.row.ID != id || r.row.Gen != gen || r.row.Status != "withdrawing" {
		return store.ErrStaleAnnouncement
	}
	r.row.Status = "withdrawn"
	return nil
}

type dao11jOrphanConnectors struct {
	store.BGPConnectorRepo
	path string
}

func (r dao11jOrphanConnectors) Get(context.Context, int) (*store.BGPConnector, error) {
	return &store.BGPConnector{ID: 7, BGPASN: 64512, VtyshPath: r.path}, nil
}

type dao11jOrphanSchedules struct{ store.ScheduledActionRepo }

func (dao11jOrphanSchedules) ListPending(context.Context) ([]store.ScheduledAction, error) {
	return nil, nil
}

type dao11jOrphanStore struct {
	store.Store
	anns *dao11jOrphanRepo
	path string
}

func (s dao11jOrphanStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.anns }
func (s dao11jOrphanStore) BGPConnectors() store.BGPConnectorRepo {
	return dao11jOrphanConnectors{path: s.path}
}
func (s dao11jOrphanStore) ScheduledActions() store.ScheduledActionRepo {
	return dao11jOrphanSchedules{}
}
func dao11jOrphanWant[T comparable](t *testing.T, name string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("ASSERT %s FAIL got=%v want=%v", name, got, want)
	} else {
		t.Logf("ASSERT %s PASS got=%v", name, got)
	}
}
func TestDao11j_R19_OrphanHoldsAnnouncementLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		path, record := filepath.Join(dir, "vtysh"), filepath.Join(dir, "commands")
		body := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '" + strings.ReplaceAll(record, "'", "'\\''") + "'\n"
		if err := os.WriteFile(path, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(record, nil, 0600); err != nil {
			t.Fatal(err)
		}
		r := &dao11jOrphanRepo{row: store.BGPAnnouncement{ID: 1, Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, Status: "orphan"}, entered: make(chan struct{}), release: make(chan struct{})}
		s := dao11jOrphanStore{anns: r, path: path}
		e := action.NewEngine(s, "auto")
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/orphan-force-withdraw", strings.NewReader(`{"announcement_id":1}`))
		c.Request.Header.Set("Content-Type", "application/json")
		done := make(chan struct{})
		go func() { orphanForceWithdraw(Dependencies{Store: s, ActionEngine: e})(c); close(done) }()
		<-r.entered
		synctest.Wait()
		metric := func() float64 {
			var m dto.Metric
			if err := metrics.BGPWithdrawingReconcile.WithLabelValues("busy").Write(&m); err != nil {
				t.Fatal(err)
			}
			return m.GetCounter().GetValue()
		}
		before := metric()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go e.RunWithdrawingReconcile(ctx, time.Minute)
		synctest.Wait()
		<-time.After(time.Minute)
		synctest.Wait()
		dao11jOrphanWant(t, "R19.Busy", metric()-before, float64(1))
		dao11jOrphanWant(t, "R19.NoClaim", r.claims.Load(), int64(0))
		commands, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		dao11jOrphanWant(t, "R19.NoVtysh", len(commands), 0)
		close(r.release)
		<-done
		synctest.Wait()
		a, _ := r.Get(context.Background(), 1)
		dao11jOrphanWant(t, "R19.Status", a.Status, "withdrawn")
		dao11jOrphanWant(t, "R19.Response", w.Code, 200)
		dao11jOrphanWant(t, "R20.Orphan", e.AnnouncementTakeovers(1), 1)
	})
}

type dao11jDismissedRepo struct{ *dao11jOrphanRepo }

func (r dao11jDismissedRepo) ForceWithdraw(context.Context, int) ([]store.BGPAnnouncementAttack, int, error) {
	// Equivalent to orphanDismiss committing after the handler's first Get,
	// before ForceWithdraw's SELECT FOR UPDATE. ForceWithdraw is a no-op.
	r.mu.Lock()
	defer r.mu.Unlock()
	r.row.Status = "dismissed"
	return nil, r.row.Gen, nil
}

type dao11jDismissedStore struct {
	dao11jOrphanStore
	r dao11jDismissedRepo
}

func (s dao11jDismissedStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.r }

func TestDao11j_R19b_OrphanNoopNoTakeover(t *testing.T) {
	r := &dao11jOrphanRepo{row: store.BGPAnnouncement{ID: 1, Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, Status: "orphan", Gen: 7}}
	s := dao11jDismissedStore{dao11jOrphanStore: dao11jOrphanStore{anns: r, path: "/usr/bin/true"}, r: dao11jDismissedRepo{r}}
	e := action.NewEngine(s, "auto")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/orphan-force-withdraw", strings.NewReader(`{"announcement_id":1}`))
	c.Request.Header.Set("Content-Type", "application/json")
	orphanForceWithdraw(Dependencies{Store: s, ActionEngine: e})(c)
	dao11jOrphanWant(t, "R19b.Response", w.Code, 200)
	dao11jOrphanWant(t, "R19b.NoFalseTakeover", e.AnnouncementTakeovers(1), 0)
}
