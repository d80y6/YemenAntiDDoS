package action

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/storetest"
)

// Embedding makes any unimplemented repository call fail instead of silently
// succeeding. The methods below model only the production paths under test.
type v3Store struct {
	store.Store
	mu           sync.Mutex
	conn         store.XDropConnector
	actions      []store.ResponseAction
	logs         []store.ActionExecutionLog
	overrides    []store.ActionManualOverride
	rules        map[string]store.XDropActiveRule
	history      map[string][]string
	schedules    []store.ScheduledAction
	flows        []store.FlowLog
	filter       store.FlowLogFilter
	bypassFilter bool
}

type v3GlobalWebhooks struct{ store.WebhookConnectorRepo }

func (v3GlobalWebhooks) ListGlobal(context.Context) ([]store.WebhookConnector, error) {
	return nil, nil
}
func (s *v3Store) WebhookConnectors() store.WebhookConnectorRepo { return v3GlobalWebhooks{} }

func newV3Store(base string) *v3Store {
	return &v3Store{conn: store.XDropConnector{ID: 7, Name: "xsight-test", APIURL: base, APIKey: v3TestKey, Enabled: true, TimeoutMs: 1000}, rules: map[string]store.XDropActiveRule{}, history: map[string][]string{}}
}

type v3Connectors struct {
	store.XDropConnectorRepo
	s *v3Store
}
type v3Targets struct{ store.XDropTargetRepo }
type v3Responses struct {
	store.ResponseRepo
	s *v3Store
}
type v3Logs struct {
	store.ActionExecLogRepo
	s *v3Store
}
type v3Active struct {
	store.XDropActiveRuleRepo
	s *v3Store
}
type v3Schedules struct {
	store.ScheduledActionRepo
	s *v3Store
}
type v3Overrides struct {
	store.ActionManualOverrideRepo
	s *v3Store
}
type v3Preconditions struct{ store.PreconditionRepo }
type v3Flows struct {
	store.FlowLogRepo
	s *v3Store
}

func (s *v3Store) XDropConnectors() store.XDropConnectorRepo       { return v3Connectors{s: s} }
func (s *v3Store) XDropTargets() store.XDropTargetRepo             { return v3Targets{} }
func (s *v3Store) Responses() store.ResponseRepo                   { return v3Responses{s: s} }
func (s *v3Store) ActionExecLog() store.ActionExecLogRepo          { return v3Logs{s: s} }
func (s *v3Store) XDropActiveRules() store.XDropActiveRuleRepo     { return v3Active{s: s} }
func (s *v3Store) ScheduledActions() store.ScheduledActionRepo     { return v3Schedules{s: s} }
func (s *v3Store) ManualOverrides() store.ActionManualOverrideRepo { return v3Overrides{s: s} }
func (s *v3Store) Preconditions() store.PreconditionRepo           { return v3Preconditions{} }
func (s *v3Store) FlowLogs() store.FlowLogRepo                     { return v3Flows{s: s} }
func (r v3Connectors) Get(_ context.Context, id int) (*store.XDropConnector, error) {
	if id != r.s.conn.ID {
		return nil, fmt.Errorf("connector not found")
	}
	c := r.s.conn
	return &c, nil
}
func (r v3Connectors) ListEnabled(context.Context) ([]store.XDropConnector, error) {
	if r.s.conn.Enabled {
		return []store.XDropConnector{r.s.conn}, nil
	}
	return nil, nil
}
func (v3Targets) List(context.Context, int) ([]store.XDropConnector, error) { return nil, nil }
func (r v3Responses) Get(context.Context, int) (*store.Response, error) {
	return &store.Response{ID: 1, Name: "v3-test", Enabled: true}, nil
}
func (r v3Responses) ListActions(context.Context, int) ([]store.ResponseAction, error) {
	return append([]store.ResponseAction(nil), r.s.actions...), nil
}
func (r v3Responses) GetAction(_ context.Context, id int) (*store.ResponseAction, error) {
	for _, a := range r.s.actions {
		if a.ID == id {
			return &a, nil
		}
	}
	return nil, fmt.Errorf("action not found")
}
func (r v3Overrides) Create(_ context.Context, row *store.ActionManualOverride) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, current := range r.s.overrides {
		if current.AttackID == row.AttackID && current.ActionID == row.ActionID && current.ConnectorID == row.ConnectorID && current.ExternalRuleID == row.ExternalRuleID {
			return current.ID, nil
		}
	}
	cp := *row
	cp.ID = len(r.s.overrides) + 1
	r.s.overrides = append(r.s.overrides, cp)
	return cp.ID, nil
}
func (r v3Overrides) ListByAttack(_ context.Context, attackID int) ([]store.ActionManualOverride, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var rows []store.ActionManualOverride
	for _, row := range r.s.overrides {
		if row.AttackID == attackID {
			rows = append(rows, row)
		}
	}
	return rows, nil
}
func (v3Preconditions) List(context.Context, int) ([]store.ActionPrecondition, error) {
	return nil, nil
}
func (r v3Logs) Create(_ context.Context, l *store.ActionExecutionLog) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	cp := *l
	cp.ID = len(r.s.logs) + 1
	r.s.logs = append(r.s.logs, cp)
	return len(r.s.logs), nil
}
func (r v3Logs) AllTargetsDone(_ context.Context, attackID, actionID int, phase string) (bool, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return storetest.TargetsDone(r.s.logs, attackID, actionID, phase), nil
}
func (r v3Logs) ListByAttack(_ context.Context, attackID int) ([]store.ActionExecutionLog, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.ActionExecutionLog
	for _, entry := range r.s.logs {
		if entry.AttackID == attackID {
			out = append(out, entry)
		}
	}
	return out, nil
}
func (r v3Active) ListByAttack(_ context.Context, attackID int) ([]store.XDropActiveRule, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.XDropActiveRule
	for _, row := range r.s.rules {
		if row.AttackID == attackID {
			out = append(out, row)
		}
	}
	return out, nil
}
func v3RuleKey(attack, action, conn int, id string) string {
	return fmt.Sprintf("%d/%d/%d/%s", attack, action, conn, id)
}
func (r v3Active) Upsert(_ context.Context, row *store.XDropActiveRule) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	key := v3RuleKey(row.AttackID, row.ActionID, row.ConnectorID, row.ExternalRuleID)
	old, exists := r.s.rules[key]
	if exists && old.Status == "withdrawn" {
		return old.ID, nil
	}
	cp := *row
	if exists {
		cp.ID = old.ID
	} else {
		cp.ID = len(r.s.rules) + 1
	}
	r.s.rules[key] = cp
	r.s.history[key] = append(r.s.history[key], row.Status)
	return r.s.rules[key].ID, nil
}
func (r v3Active) mark(attack, action, conn int, id, status string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	key := v3RuleKey(attack, action, conn, id)
	row, ok := r.s.rules[key]
	if !ok {
		return fmt.Errorf("rule row not found")
	}
	if status == "failed" && row.Status == "withdrawn" || status == "delayed" && row.Status != "active" && row.Status != "failed" {
		return nil
	}
	row.Status = status
	if status == "withdrawn" {
		row.ErrorMessage = ""
	}
	r.s.rules[key] = row
	r.s.history[key] = append(r.s.history[key], status)
	return nil
}
func (r v3Active) MarkWithdrawing(_ context.Context, a, b, c int, id string) (bool, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	key := v3RuleKey(a, b, c, id)
	row, ok := r.s.rules[key]
	if !ok || (row.Status != "active" && row.Status != "delayed" && row.Status != "failed") {
		return false, nil
	}
	row.Status = "withdrawing"
	r.s.rules[key] = row
	r.s.history[key] = append(r.s.history[key], row.Status)
	return true, nil
}
func (r v3Active) MarkWithdrawn(_ context.Context, a, b, c int, id string) error {
	return r.mark(a, b, c, id, "withdrawn")
}
func (r v3Active) MarkFailed(_ context.Context, a, b, c int, id, msg string) error {
	return r.mark(a, b, c, id, "failed")
}
func (r v3Active) MarkDelayed(_ context.Context, a, b, c int, id string, minutes int) error {
	return r.mark(a, b, c, id, "delayed")
}
func (r v3Schedules) Schedule(_ context.Context, row *store.ScheduledAction) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	copy := *row
	copy.ID = len(r.s.schedules) + 1
	copy.Status = "pending"
	r.s.schedules = append(r.s.schedules, copy)
	return copy.ID, nil
}

func (r v3Schedules) ListPending(context.Context) ([]store.ScheduledAction, error) {
	return r.listStatus("pending"), nil
}

func (r v3Schedules) ListExecuting(context.Context) ([]store.ScheduledAction, error) {
	return r.listStatus("executing"), nil
}

func (r v3Schedules) listStatus(status string) []store.ScheduledAction {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var rows []store.ScheduledAction
	for _, row := range r.s.schedules {
		if row.Status == status {
			rows = append(rows, row)
		}
	}
	return rows
}
func (r v3Schedules) mark(id int, status string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if id <= 0 || id > len(r.s.schedules) {
		return fmt.Errorf("schedule not found")
	}
	r.s.schedules[id-1].Status = status
	return nil
}
func (r v3Schedules) MarkExecuting(ctx context.Context, id int) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if id <= 0 || id > len(r.s.schedules) || r.s.schedules[id-1].Status != "pending" {
		return fmt.Errorf("scheduled_action %d: %w", id, store.ErrNotPending)
	}
	r.s.schedules[id-1].Status = "executing"
	return nil
}
func (r v3Schedules) Complete(_ context.Context, id int) error         { return r.mark(id, "completed") }
func (r v3Schedules) Fail(_ context.Context, id int, msg string) error { return r.mark(id, "failed") }
func (r v3Flows) QueryByDstIP(_ context.Context, f store.FlowLogFilter) ([]store.FlowLog, error) {
	r.s.filter = f
	var out []store.FlowLog
	for _, flow := range r.s.flows {
		if !r.s.bypassFilter {
			match := len(f.Protocols) == 0
			for _, p := range f.Protocols {
				match = match || flow.Protocol == p
			}
			if !match || flow.TCPFlags&int(f.TCPFlagsAll) != int(f.TCPFlagsAll) || flow.TCPFlags&int(f.TCPFlagsNone) != 0 {
				continue
			}
		}
		out = append(out, flow)
	}
	return out, nil
}
func (r v3Flows) QueryBySrcIP(ctx context.Context, f store.FlowLogFilter) ([]store.FlowLog, error) {
	return r.QueryByDstIP(ctx, f)
}
func (s *v3Store) logSnapshot() []store.ActionExecutionLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.ActionExecutionLog(nil), s.logs...)
}
func (s *v3Store) state(attack, action int, id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rules[v3RuleKey(attack, action, s.conn.ID, id)].Status
}
func v3Eventually(duration time.Duration, check func() bool) bool {
	deadline := time.Now().Add(duration)
	for {
		if check() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}
