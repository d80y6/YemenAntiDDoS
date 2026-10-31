package tests

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/metrics"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// All fixtures use existing repository interfaces so the same files run on HEAD.
type dao14c2Store struct {
	store.Store
	responses store.ResponseRepo
	logs      store.ActionExecLogRepo
	anns      store.BGPAnnouncementRepo
	schedules store.ScheduledActionRepo
	attacks   store.AttackRepo
	shell     store.ShellConnectorRepo
	rules     store.XDropActiveRuleRepo
	webhooks  store.WebhookConnectorRepo
}

func (s dao14c2Store) WebhookConnectors() store.WebhookConnectorRepo {
	if s.webhooks != nil {
		return s.webhooks
	}
	return s.Store.WebhookConnectors()
}

type dao14c2Webhooks struct{ store.WebhookConnectorRepo }

func (dao14c2Webhooks) Get(context.Context, int) (*store.WebhookConnector, error) {
	return &store.WebhookConnector{ID: 7, Name: "dao14c2", URL: "http://dao14c2.invalid", Enabled: true}, nil
}

func (s dao14c2Store) Responses() store.ResponseRepo {
	if s.responses != nil {
		return s.responses
	}
	return s.Store.Responses()
}
func (s dao14c2Store) ActionExecLog() store.ActionExecLogRepo {
	if s.logs != nil {
		return s.logs
	}
	return s.Store.ActionExecLog()
}
func (s dao14c2Store) BGPAnnouncements() store.BGPAnnouncementRepo {
	if s.anns != nil {
		return s.anns
	}
	return s.Store.BGPAnnouncements()
}
func (s dao14c2Store) ScheduledActions() store.ScheduledActionRepo {
	if s.schedules != nil {
		return s.schedules
	}
	return s.Store.ScheduledActions()
}
func (s dao14c2Store) Attacks() store.AttackRepo {
	if s.attacks != nil {
		return s.attacks
	}
	return s.Store.Attacks()
}
func (s dao14c2Store) ShellConnectors() store.ShellConnectorRepo {
	if s.shell != nil {
		return s.shell
	}
	return s.Store.ShellConnectors()
}
func (s dao14c2Store) XDropActiveRules() store.XDropActiveRuleRepo {
	if s.rules != nil {
		return s.rules
	}
	return s.Store.XDropActiveRules()
}

func dao14c2Want(t *testing.T, name string, ok bool, detail any) {
	t.Helper()
	if !ok {
		t.Errorf("ASSERT %s FAIL: %v", name, detail)
	} else {
		t.Logf("ASSERT %s PASS: %v", name, detail)
	}
}

type dao14c2Transport func(*http.Request) (*http.Response, error)

func (f dao14c2Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func dao14c2OK(r *http.Request) (*http.Response, error) {
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
}

type dao14c2Probe struct {
	mu    sync.Mutex
	ctx   context.Context
	armed atomic.Bool
}

func (p *dao14c2Probe) exhaust(ctx context.Context) {
	p.mu.Lock()
	p.ctx = ctx
	p.mu.Unlock()
	<-ctx.Done()
}
func (p *dao14c2Probe) current() context.Context { p.mu.Lock(); defer p.mu.Unlock(); return p.ctx }

type dao14c2Responses struct {
	store.ResponseRepo
	probe  *dao14c2Probe
	calls  atomic.Int32
	repeat bool
}

func (r *dao14c2Responses) Get(ctx context.Context, id int) (*store.Response, error) {
	n := r.calls.Add(1)
	if n == 2 || (r.repeat && n%2 == 0) {
		r.probe.exhaust(ctx)
	}
	return r.ResponseRepo.Get(ctx, id)
}

type dao14c2Observation struct {
	ctxErr, actionErr error
	budget            time.Duration
	deadline          bool
	row               store.ActionExecutionLog
}
type dao14c2Logs struct {
	store.ActionExecLogRepo
	probe        *dao14c2Probe
	mu           sync.Mutex
	observations []dao14c2Observation
}

func (r *dao14c2Logs) Create(ctx context.Context, row *store.ActionExecutionLog) (int, error) {
	d, has := ctx.Deadline()
	o := dao14c2Observation{ctxErr: ctx.Err(), budget: time.Until(d), deadline: has, row: *row}
	if c := r.probe.current(); c != nil {
		o.actionErr = c.Err()
	}
	r.mu.Lock()
	r.observations = append(r.observations, o)
	r.mu.Unlock()
	// Match pgx: an expired context cannot persist a row.
	if o.ctxErr != nil {
		return 0, o.ctxErr
	}
	return r.ActionExecLogRepo.Create(ctx, row)
}
func (r *dao14c2Logs) snapshot() []dao14c2Observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]dao14c2Observation(nil), r.observations...)
}

type dao14c2Shell struct {
	store.ShellConnectorRepo
	before  func()
	enabled bool
}

func (r dao14c2Shell) Get(context.Context, int) (*store.ShellConnector, error) {
	if r.before != nil {
		r.before()
	}
	return &store.ShellConnector{ID: 7, Name: "dao14c2", Command: "/usr/bin/true", Enabled: r.enabled}, nil
}

func dao14c2BGP(ms *MockStore) {
	ms.responses.actions[0].BGPConnectorID = intPtr(7)
	ms.responses.actions[0].BGPRouteMap = "RTBH"
	ms.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Name: "dao14c2", Enabled: true, BGPASN: 64512, VtyshPath: "/usr/bin/true"}}
}
func dao14c2Counters(kind string) map[string]float64 {
	out := map[string]float64{}
	for _, status := range []string{"success", "failed", "scheduled", "skipped", "timeout"} {
		out[status] = testutil.ToFloat64(metrics.ActionExecutions.WithLabelValues(kind, status))
	}
	return out
}
func dao14c2ExecAssertions(t *testing.T, ms *MockStore, logs *dao14c2Logs, index int, before map[string]float64, status, reason string, legacy bool) {
	t.Helper()
	obs := logs.snapshot()
	if len(obs) != index+1 {
		t.Fatalf("DEVICE Create calls=%d want=%d", len(obs), index+1)
	}
	o := obs[index]
	if o.actionErr != context.DeadlineExceeded {
		t.Fatalf("DEVICE action context at Create=%v", o.actionErr)
	}
	t.Log("ASSERT Device PASS: action context was DeadlineExceeded at Create")
	dao14c2Want(t, "CtxLive", o.ctxErr == nil, o.ctxErr)
	dao14c2Want(t, "Budget", o.deadline && o.budget > 0 && o.budget <= 5*time.Second, fmt.Sprintf("deadline=%v remaining=%v", o.deadline, o.budget))
	rows := ms.actionExecLog.snapshotLogs()
	persisted := len(rows) == index+1
	if persisted {
		row := rows[index]
		if legacy {
			persisted = row.TriggerPhase == "on_expired"
		} else {
			persisted = row.Status == status && row.SkipReason == reason
		}
		if strings.Contains(t.Name(), "BGP.Unknown") {
			persisted = persisted && strings.Contains(row.ErrorMessage, "outcome unknown (ctx ended)")
		}
	}
	dao14c2Want(t, "Persisted", persisted, rows)
	delta := dao14c2Counters(o.row.ActionType)[o.row.Status] - before[o.row.Status]
	dao14c2Want(t, "Counter", delta == 1 && len(rows)-index == 1, fmt.Sprintf("counter delta=%v row delta=%d", delta, len(rows)-index))
}

func TestDao14c2_E1(t *testing.T) {
	for _, tc := range []struct{ name, kind, status, reason string }{
		{"Webhook", "webhook", "failed", ""},
		{"XDropGlobal", "xdrop", "skipped", action.SkipReasonGlobalNoTarget},
		{"XDropOuter", "xdrop", "skipped", action.SkipReasonNoConnector},
		{"Shell", "shell", "timeout", ""},
		{"BGPGlobal", "bgp", "skipped", action.SkipReasonGlobalNoTarget},
		{"BGPNoConnector", "bgp", "skipped", action.SkipReasonNoConnector},
		{"BGP.Unknown", "bgp", "failed", ""},
		{"BGP.ManualOverride", "bgp", "skipped", action.SkipReasonManualOverride},
		{"XDropAPI", "xdrop_api", "skipped", action.SkipReasonDeprecatedXDropAPI},
		{"Unknown", "unknown", "skipped", action.SkipReasonUnknownActionType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				old := action.WebhookTransport
				action.WebhookTransport = dao14c2Transport(dao14c2OK)
				defer func() { action.WebhookTransport = old }()
				ms, _, ev := dao4Fixture(tc.kind, "once", "on_detected")
				probe := &dao14c2Probe{}
				resp := &dao14c2Responses{ResponseRepo: ms.Responses(), probe: probe}
				logs := &dao14c2Logs{ActionExecLogRepo: ms.ActionExecLog(), probe: probe}
				s := dao14c2Store{Store: ms, responses: resp, logs: metrics.WrapActionExecLog(logs), shell: dao14c2Shell{enabled: true}}
				if strings.HasSuffix(tc.name, "Global") {
					ev.Attack.DstIP = "0.0.0.0/0"
				}
				if tc.name == "Webhook" {
					ms.responses.actions[0].WebhookConnectorID = intPtr(7)
					s.webhooks = dao14c2Webhooks{ms.WebhookConnectors()}
				}
				if tc.kind == "shell" {
					ms.responses.actions[0].ShellConnectorID = intPtr(7)
				}
				if strings.HasPrefix(tc.name, "BGP.") {
					dao14c2BGP(ms)
				}
				if tc.name == "BGP.ManualOverride" {
					_, err := ms.ManualOverrides().Create(context.Background(), &store.ActionManualOverride{AttackID: 20, ActionID: 10, ConnectorID: 7, ExternalRuleID: "192.0.2.10/32|RTBH"})
					if err != nil {
						t.Fatal(err)
					}
				}
				before := dao14c2Counters(tc.kind)
				action.NewEngine(s, "auto").HandleEvent(ev)
				synctest.Wait()
				<-time.After(31 * time.Second)
				synctest.Wait()
				if resp.calls.Load() != 2 {
					t.Fatalf("DEVICE Responses.Get=%d want=2", resp.calls.Load())
				}
				dao14c2ExecAssertions(t, ms, logs, 0, before, tc.status, tc.reason, false)
			})
		})
	}
}

type dao14c2Schedules struct {
	store.ScheduledActionRepo
	probe *dao14c2Probe
	mu    sync.Mutex
	final []struct {
		ctx context.Context
		err error
	}
}

func (r *dao14c2Schedules) MarkExecuting(ctx context.Context, id int) error {
	err := r.ScheduledActionRepo.MarkExecuting(ctx, id)
	if err == nil {
		r.probe.armed.Store(true)
	}
	return err
}
func (r *dao14c2Schedules) record(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.final = append(r.final, struct {
		ctx context.Context
		err error
	}{ctx, ctx.Err()})
}
func (r *dao14c2Schedules) Fail(ctx context.Context, id int, msg string) error {
	r.record(ctx)
	return r.ScheduledActionRepo.Fail(ctx, id, msg)
}
func (r *dao14c2Schedules) Complete(ctx context.Context, id int) error {
	r.record(ctx)
	return r.ScheduledActionRepo.Complete(ctx, id)
}
func (r *dao14c2Schedules) check(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	ok := len(r.final) == 1 && r.final[0].ctx == r.probe.current() && r.final[0].err == context.DeadlineExceeded
	dao14c2Want(t, "FinalizeCtx", ok, r.final)
}

type dao14c2Announcements struct {
	store.BGPAnnouncementRepo
	probe  *dao14c2Probe
	worker bool
}

func (r dao14c2Announcements) Get(ctx context.Context, id int) (*store.BGPAnnouncement, error) {
	if !r.worker && r.probe.armed.CompareAndSwap(true, false) {
		r.probe.exhaust(ctx)
	}
	return r.BGPAnnouncementRepo.Get(ctx, id)
}
func (r dao14c2Announcements) MarkWithdrawing(ctx context.Context, id, gen int) (bool, error) {
	if r.worker {
		r.probe.exhaust(ctx)
	}
	return r.BGPAnnouncementRepo.MarkWithdrawing(ctx, id, gen)
}

type dao14c2Attacks struct {
	store.AttackRepo
	probe *dao14c2Probe
}

func (r dao14c2Attacks) Get(ctx context.Context, id int) (*store.Attack, error) {
	if r.probe.armed.CompareAndSwap(true, false) {
		r.probe.exhaust(ctx)
	}
	return r.AttackRepo.Get(ctx, id)
}

func dao14c2Recovered(t *testing.T, legacy bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		ms, _, ev := dao4Fixture("bgp", "once", "on_expired")
		dao14c2BGP(ms)
		probe := &dao14c2Probe{}
		logs := &dao14c2Logs{ActionExecLogRepo: ms.ActionExecLog(), probe: probe}
		sched := &dao14c2Schedules{ScheduledActionRepo: ms.ScheduledActions(), probe: probe}
		s := dao14c2Store{Store: ms, logs: metrics.WrapActionExecLog(logs), schedules: sched}
		sa := &store.ScheduledAction{ActionType: "bgp_withdraw", AttackID: 20, ActionID: 10, ConnectorID: 7, ScheduledFor: time.Now().Add(-time.Second)}
		if legacy {
			id, err := ms.Attacks().Create(context.Background(), ev.Attack)
			if err != nil {
				t.Fatal(err)
			}
			sa.AttackID = id
			s.attacks = dao14c2Attacks{ms.Attacks(), probe}
		} else {
			a, err := ms.BGPAnnouncements().Attach(context.Background(), store.BGPAttachParams{AttackID: 20, ActionID: intPtr(10), Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ms.BGPAnnouncements().Detach(context.Background(), 20, "192.0.2.10/32", "RTBH", 7)
			if err != nil {
				t.Fatal(err)
			}
			sa.AnnouncementID = &a.AnnouncementID
			s.anns = dao14c2Announcements{BGPAnnouncementRepo: ms.BGPAnnouncements(), probe: probe}
		}
		if _, err := ms.ScheduledActions().Schedule(context.Background(), sa); err != nil {
			t.Fatal(err)
		}
		before := dao14c2Counters("bgp")
		if err := action.NewEngine(s, "auto").RecoverScheduledActions(context.Background()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		<-time.After(31 * time.Second)
		synctest.Wait()
		dao14c2ExecAssertions(t, ms, logs, 0, before, "failed", "", legacy)
		sched.check(t)
	})
}
func TestDao14c2_E2(t *testing.T) {
	t.Run("RecoveredByAnnouncement", func(t *testing.T) { dao14c2Recovered(t, false) })
}
func TestDao14c2_E3(t *testing.T) {
	t.Run("RecoveredLegacy", func(t *testing.T) { dao14c2Recovered(t, true) })
}
func TestDao14c2_E4(t *testing.T) {
	t.Run("DelayedWorker", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ms, _, ev := dao4Fixture("bgp", "once", "on_expired")
			ev.Type = "expired"
			dao14c2BGP(ms)
			ms.responses.actions[0].BGPWithdrawDelayMinutes = 1
			a, err := ms.BGPAnnouncements().Attach(context.Background(), store.BGPAttachParams{AttackID: 20, ActionID: intPtr(10), Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, DelayMinutes: 1})
			if err != nil {
				t.Fatal(err)
			}
			if err := ms.BGPAnnouncements().MarkAnnounced(context.Background(), a.AnnouncementID, a.Gen); err != nil {
				t.Fatal(err)
			}
			probe := &dao14c2Probe{}
			logs := &dao14c2Logs{ActionExecLogRepo: ms.ActionExecLog(), probe: probe}
			sched := &dao14c2Schedules{ScheduledActionRepo: ms.ScheduledActions(), probe: probe}
			s := dao14c2Store{Store: ms, logs: metrics.WrapActionExecLog(logs), schedules: sched, anns: dao14c2Announcements{BGPAnnouncementRepo: ms.BGPAnnouncements(), probe: probe, worker: true}}
			action.NewEngine(s, "auto").HandleEvent(ev)
			synctest.Wait()
			rows := ms.actionExecLog.snapshotLogs()
			if len(rows) != 1 || rows[0].Status != "scheduled" {
				t.Fatalf("DEVICE scheduled row=%+v", rows)
			}
			before := dao14c2Counters("bgp")
			<-time.After(91 * time.Second)
			synctest.Wait()
			dao14c2ExecAssertions(t, ms, logs, 1, before, "failed", "", false)
			sched.check(t)
		})
	})
}
