package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/prometheus/client_golang/prometheus"
)

type dao13cCounts struct {
	store.BGPAnnouncementRepo
	calls int
	err   error
}

func (r *dao13cCounts) CountLiveByConnector(c context.Context, id int) (int, error) {
	r.calls++
	if r.err != nil {
		return 0, r.err
	}
	return r.BGPAnnouncementRepo.CountLiveByConnector(c, id)
}

type dao13cDelete struct {
	store.BGPConnectorRepo
	calls int
}

func (r *dao13cDelete) Delete(c context.Context, id int) error {
	r.calls++
	return r.BGPConnectorRepo.Delete(c, id)
}

type dao13cAPIStore struct {
	store.Store
	anns       *dao13cCounts
	connectors *dao13cDelete
}

func (s dao13cAPIStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.anns }
func (s dao13cAPIStore) BGPConnectors() store.BGPConnectorRepo       { return s.connectors }

func dao13cDeleteRequest(t *testing.T, s store.Store) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/settings/bgp-connectors/7", nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	setupRouter(s).ServeHTTP(w, req)
	return w
}

func TestDao13c_K1(t *testing.T) {
	for _, status := range []string{"announcing", "active", "delayed", "withdrawing", "failed", "orphan", "withdrawn", "dismissed", "dismissed_on_upgrade", "query_error", "action_reference"} {
		t.Run(status, func(t *testing.T) {
			ms := NewMockStore()
			ms.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Name: "dao13c", BGPASN: 65000}}
			ms.bgpAnnouncements.announcements = []store.BGPAnnouncement{{ID: 1, ConnectorID: 7, Prefix: "192.0.2.241/32", Status: status}}
			r := &dao13cCounts{BGPAnnouncementRepo: ms.BGPAnnouncements()}
			d := &dao13cDelete{BGPConnectorRepo: ms.BGPConnectors()}
			want, deletes, counts := http.StatusConflict, 0, 1
			switch status {
			case "withdrawn", "dismissed", "dismissed_on_upgrade":
				want, deletes = http.StatusOK, 1
			case "query_error":
				r.err = errors.New("announcement count unavailable")
				want = http.StatusInternalServerError
			case "action_reference":
				ms.responses.actions = []store.ResponseAction{{ID: 1, BGPConnectorID: intPtr(7)}}
				counts = 0
			}
			w := dao13cDeleteRequest(t, dao13cAPIStore{ms, r, d})
			dao11jWant(t, "K1."+status+".HTTP", w.Code, want)
			dao11jWant(t, "K1."+status+".Deletes", d.calls, deletes)
			dao11jWant(t, "K1."+status+".CountCalls", r.calls, counts)
			if want == http.StatusConflict && counts > 0 {
				dao11jWant(t, "K1."+status+".Message", strings.Contains(w.Body.String(), "connector still has 1 announcements in FRR-relevant states"), true)
			}
		})
	}
}

func TestDao13c_F6(t *testing.T) {
	if os.Getenv("XSIGHT_DAO13C_METRICS_CHILD") != "1" {
		path, err := os.Executable()
		dao5bCheck(t, err)
		cmd := exec.Command(path, "-test.run=^TestDao13c_F6$", "-test.v")
		cmd.Env = append(os.Environ(), "XSIGHT_DAO13C_METRICS_CHILD=1")
		out, err := cmd.CombinedOutput()
		t.Log(string(out))
		dao5bCheck(t, err)
		return
	}
	metrics.BGPWithdrawingReconcile.Reset()
	reg := prometheus.NewRegistry()
	ms := NewMockStore()
	dao5bCheck(t, metrics.Register(reg, ms, dao4Tracker(ms, nil)))
	families, err := reg.Gather()
	dao5bCheck(t, err)
	seen := map[string]bool{}
	for _, family := range families {
		if family.GetName() == "xsight_bgp_withdrawing_reconcile_total" {
			for _, metric := range family.Metric {
				for _, label := range metric.Label {
					if label.GetName() == "outcome" {
						seen[label.GetValue()] = true
					}
				}
			}
		}
	}
	for _, outcome := range []string{"failed_claimed", "failed_busy", "failed_claim_lost", "failed_claim_error", "failed_list_error"} {
		t.Run(outcome, func(t *testing.T) {
			dao11jWant(t, "F6."+outcome, seen[outcome], true)
		})
	}
}
