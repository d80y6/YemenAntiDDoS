package postgres

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

func dao4Migrate(t *testing.T, db *PGStore) {
	t.Helper()
	if err := db.AutoMigrate(context.Background(), RetentionConfig{TSStatsDays: 7, TSStatsCompressDays: 1, TSStatsCaggDays: 90, FlowLogsDays: 7, FlowLogsCompressDays: 1}); err != nil {
		t.Fatal(err)
	}
}
func dao4BootstrapLog(t *testing.T, db *PGStore, kind string, attack, act int, rule, phase string) {
	t.Helper()
	cid := 7
	if _, err := db.ActionExecLog().Create(context.Background(), &store.ActionExecutionLog{AttackID: attack, ActionID: act, ConnectorID: &cid, ActionType: kind, ExternalRuleID: rule, TriggerPhase: phase, Status: "success"}); err != nil {
		t.Fatal(err)
	}
}
func dao4BootstrapCount(t *testing.T, db *PGStore, kind, rule string, attack, act int) int {
	t.Helper()
	var n int
	var err error
	if kind == "xdrop" {
		err = db.Pool().QueryRow(context.Background(), `SELECT count(*) FROM xdrop_active_rules WHERE attack_id=$1 AND action_id=$2 AND connector_id=7 AND external_rule_id=$3`, attack, act, rule).Scan(&n)
	} else {
		err = db.Pool().QueryRow(context.Background(), `SELECT count(*) FROM bgp_announcements a JOIN bgp_announcement_attacks b ON b.announcement_id=a.id WHERE b.attack_id=$1 AND b.action_id=$2 AND a.connector_id=7 AND a.prefix||'|'||a.route_map=$3`, attack, act, rule).Scan(&n)
	}
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func TestDao4_B20_OverrideExcludesBootstrap(t *testing.T) {
	for _, kind := range []string{"xdrop", "bgp"} {
		t.Run(kind, func(t *testing.T) {
			db := newPostgresContractBackend(t).(*postgresContractBackend).db
			if kind == "bgp" {
				dao13dOldBGP(t, db)
			}
			rule := "192.0.2.10/32|RTBH"
			dao4BootstrapLog(t, db, kind, 20, 10, rule, "on_detected")
			dao4BootstrapLog(t, db, "manual_override", 20, 10, rule, "manual_override")
			dao4Migrate(t, db)
			if n := dao4BootstrapCount(t, db, kind, rule, 20, 10); n != 0 {
				t.Errorf("overridden bootstrap rows=%d; want 0", n)
			}
			if kind == "bgp" {
				rows, err := db.BGPAnnouncements().ListActive(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if len(rows) != 0 {
					t.Fatalf("overridden announcement rows=%+v; want none", rows)
				}
			}
		})
	}
}
func TestDao4_B20c_ExistingAnnouncementExcludesAttachment(t *testing.T) {
	db := newPostgresContractBackend(t).(*postgresContractBackend).db
	dao13dOldBGP(t, db)
	rule := "192.0.2.10/32|RTBH"
	dao4BootstrapLog(t, db, "bgp", 20, 10, rule, "on_detected")
	dao4BootstrapLog(t, db, "bgp", 21, 11, rule, "on_detected")
	dao4BootstrapLog(t, db, "manual_override", 20, 10, rule, "manual_override")
	dao4Migrate(t, db)
	if n := dao4BootstrapCount(t, db, "bgp", rule, 20, 10); n != 0 {
		t.Fatalf("overridden attachment count=%d; want 0", n)
	}
	if n := dao4BootstrapCount(t, db, "bgp", rule, 21, 11); n != 1 {
		t.Fatalf("unaffected attachment count=%d; want 1", n)
	}
	a, err := db.BGPAnnouncements().FindByBusinessKey(context.Background(), "192.0.2.10/32", "RTBH", 7)
	if err != nil || a == nil || a.Refcount != 1 {
		t.Fatalf("announcement=%+v err=%v; want refcount 1", a, err)
	}
}
func TestDao4_B20b_OverrideOnlyOneAction(t *testing.T) {
	db := newPostgresContractBackend(t).(*postgresContractBackend).db
	rule := "shared-v3"
	for _, a := range []int{10, 11} {
		dao4BootstrapLog(t, db, "xdrop", 20, a, rule, "on_detected")
	}
	dao4BootstrapLog(t, db, "manual_override", 20, 10, rule, "manual_override")
	dao4Migrate(t, db)
	if n := dao4BootstrapCount(t, db, "xdrop", rule, 20, 11); n != 1 {
		t.Fatalf("action Y rows=%d; want 1", n)
	}
}
func TestDao4_B21_OtherRuleOverrideDoesNotBlock(t *testing.T) {
	for _, kind := range []string{"xdrop", "bgp"} {
		t.Run(kind, func(t *testing.T) {
			db := newPostgresContractBackend(t).(*postgresContractBackend).db
			if kind == "bgp" {
				dao13dOldBGP(t, db)
			}
			r1, r2 := "192.0.2.10/32|RTBH", "192.0.2.11/32|RTBH"
			dao4BootstrapLog(t, db, kind, 20, 10, r1, "on_detected")
			dao4BootstrapLog(t, db, "manual_override", 20, 10, r2, "manual_override")
			dao4Migrate(t, db)
			if n := dao4BootstrapCount(t, db, kind, r1, 20, 10); n != 1 {
				t.Fatalf("R1 rows=%d; want 1", n)
			}
		})
	}
}
func TestDao4_B21c_CreatedOverriddenRuleExcluded(t *testing.T) {
	for _, kind := range []string{"xdrop", "bgp"} {
		t.Run(kind, func(t *testing.T) {
			db := newPostgresContractBackend(t).(*postgresContractBackend).db
			if kind == "bgp" {
				dao13dOldBGP(t, db)
			}
			rule := "192.0.2.11/32|RTBH"
			dao4BootstrapLog(t, db, kind, 20, 10, rule, "on_detected")
			dao4BootstrapLog(t, db, "manual_override", 20, 10, rule, "manual_override")
			dao4Migrate(t, db)
			if n := dao4BootstrapCount(t, db, kind, rule, 20, 10); n != 0 {
				t.Fatalf("R2 rows=%d; want 0", n)
			}
		})
	}
}
func TestDao4_B21b_LegacyPhaseBootstrap(t *testing.T) {
	for _, kind := range []string{"xdrop", "bgp"} {
		t.Run(kind, func(t *testing.T) {
			db := newPostgresContractBackend(t).(*postgresContractBackend).db
			if kind == "bgp" {
				dao13dOldBGP(t, db)
			}
			rule := "192.0.2.10/32|RTBH"
			dao4BootstrapLog(t, db, kind, 20, 10, rule, "confirmed")
			dao4Migrate(t, db)
			if n := dao4BootstrapCount(t, db, kind, rule, 20, 10); n != 1 {
				t.Fatalf("legacy bootstrap rows=%d; want 1", n)
			}
			if kind == "xdrop" {
				dao4BootstrapUnblock(t, db)
			}
		})
	}
}

type dao4BootstrapStore struct {
	*PGStore
	logs *dao4BootstrapLogs
}

func (s dao4BootstrapStore) Responses() store.ResponseRepo { return dao4BootstrapResponses{} }
func (s dao4BootstrapStore) XDropConnectors() store.XDropConnectorRepo {
	return dao4BootstrapConnectors{}
}
func (s dao4BootstrapStore) ActionExecLog() store.ActionExecLogRepo { return s.logs }

type dao4BootstrapResponses struct{ store.ResponseRepo }

func (dao4BootstrapResponses) Get(context.Context, int) (*store.Response, error) {
	return &store.Response{ID: 1, Enabled: true}, nil
}
func (dao4BootstrapResponses) GetAction(context.Context, int) (*store.ResponseAction, error) {
	return &store.ResponseAction{ID: 10}, nil
}
func (dao4BootstrapResponses) ListActions(context.Context, int) ([]store.ResponseAction, error) {
	return []store.ResponseAction{{ID: 11, ResponseID: 1, ActionType: "xdrop", TriggerPhase: "on_expired", RunMode: "once", XDropAction: "unblock", Enabled: true}}, nil
}

type dao4BootstrapConnectors struct{ store.XDropConnectorRepo }

func (dao4BootstrapConnectors) ListEnabled(context.Context) ([]store.XDropConnector, error) {
	return []store.XDropConnector{{ID: 7, APIURL: "http://dao4.invalid", Enabled: true}}, nil
}

func (r dao4BootstrapConnectors) Get(ctx context.Context, id int) (*store.XDropConnector, error) {
	rows, err := r.ListEnabled(ctx)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.ID == id {
			return &row, nil
		}
	}
	return nil, nil
}

type dao4BootstrapLogs struct {
	store.ActionExecLogRepo
	done chan store.ActionExecutionLog
}

func (r *dao4BootstrapLogs) Create(ctx context.Context, l *store.ActionExecutionLog) (int, error) {
	id, err := r.ActionExecLogRepo.Create(ctx, l)
	if l.ActionID == 11 {
		r.done <- *l
	}
	return id, err
}

type dao4BootstrapTransport struct{ request chan string }

func (r dao4BootstrapTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.request <- req.Method + " " + req.URL.Query().Get("claim_ref")
	return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}
func dao4BootstrapUnblock(t *testing.T, db *PGStore) {
	t.Helper()
	done := make(chan store.ActionExecutionLog, 1)
	requests := make(chan string, 1)
	previous := http.DefaultTransport
	http.DefaultTransport = dao4BootstrapTransport{requests}
	t.Cleanup(func() { http.DefaultTransport = previous })
	s := dao4BootstrapStore{db, &dao4BootstrapLogs{db.ActionExecLog(), done}}
	e := action.NewEngine(s, "auto")
	rid := 1
	e.HandleEvent(tracker.AttackEvent{Type: "expired", DBID: 20, Attack: &store.Attack{ID: 20, DstIP: "192.0.2.10", DecoderFamily: "udp", ResponseID: &rid, StartedAt: time.Now()}})
	select {
	case l := <-done:
		if l.Status != "success" {
			t.Fatalf("unblock log=%+v", l)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("unblock worker did not finish")
	}
	select {
	case request := <-requests:
		if request != "DELETE a20.x10" {
			t.Fatalf("unblock request=%s", request)
		}
	default:
		t.Fatal("bootstrap rule was not deleted")
	}
	rows, err := db.XDropActiveRules().ListByAttack(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Status != "withdrawn" {
		t.Fatalf("bootstrap then unblock state=%+v", rows)
	}
}
