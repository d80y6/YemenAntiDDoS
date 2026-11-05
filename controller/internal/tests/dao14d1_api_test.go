package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/api"
	"github.com/d80y6/YemenDDoS/controller/internal/configpub"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/baseline"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/threshold"
	"github.com/d80y6/YemenDDoS/controller/internal/ingestion"
	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Faults and captured values belong to one request fixture. Embedded repositories
// provide unrelated behavior without changing any shared mock implementation.
type dao14d1Store struct {
	store.Store
	faults                   map[string]error
	calls                    map[string]int
	writes, sequence         []string
	prefixes                 map[int]store.WatchPrefix
	templates                map[int]store.ThresholdTemplate
	rules                    map[int][]store.Threshold
	thresholds               map[int]*store.Threshold
	responses                map[int]store.Response
	actions                  map[int]store.ResponseAction
	responseActions          map[int][]store.ResponseAction
	responseUpdate           *store.Response
	templateUpdate           *store.ThresholdTemplate
	thresholdUpdate          *store.Threshold
	listenerWrite            *store.FlowListener
	sourceWrite              *store.FlowSource
	duplicateName            string
	audit                    *store.AuditLog
	audits, pushes, versions int
	viewer                   bool
}

func dao14d1Fixture() *dao14d1Store {
	return &dao14d1Store{
		Store: NewMockStore(), faults: map[string]error{}, calls: map[string]int{},
		prefixes:  map[int]store.WatchPrefix{1: {ID: 1, Prefix: "192.0.2.0/24", Enabled: true}},
		templates: map[int]store.ThresholdTemplate{1: {ID: 1, Name: "t-old"}, 5: {ID: 5, Name: "t-delete"}},
		rules:     map[int][]store.Threshold{},
		thresholds: map[int]*store.Threshold{
			22: {ID: 22, PrefixID: intPtr(1), Domain: "subnet", Direction: "receives", Decoder: "ip", Unit: "pps", Comparison: "over", Value: 1000, Enabled: true},
			23: {ID: 23, TemplateID: intPtr(1), Domain: "subnet", Direction: "receives", Decoder: "ip", Unit: "pps", Comparison: "over", Value: 1000, Enabled: true},
		},
		responses:       map[int]store.Response{1: {ID: 1, Name: "r-old", Description: "d-old", Enabled: true, ActionCount: 3}},
		actions:         map[int]store.ResponseAction{10: {ID: 10, ResponseID: 1, ActionType: store.ActionTypeXDrop, TriggerPhase: "on_detected", RunMode: "once", Execution: "automatic", Enabled: true, XDropAction: "filter_l4", XDropCustomPayload: json.RawMessage("{\"dst_ip\":\"192.0.2.1\"}")}},
		responseActions: map[int][]store.ResponseAction{},
	}
}
func (s *dao14d1Store) hit(key string, write bool) error {
	s.calls[key]++
	if write {
		s.writes = append(s.writes, key)
	}
	return s.faults[key]
}
func (s *dao14d1Store) SendConfigPush(string, *pb.WatchConfig, uint64) error { s.pushes++; return nil }

type dao14d1Users struct {
	store.UserRepo
	s *dao14d1Store
}

func (s *dao14d1Store) Users() store.UserRepo { return dao14d1Users{s.Store.Users(), s} }

type dao14d1Nodes struct {
	store.NodeRepo
	s *dao14d1Store
}

func (s *dao14d1Store) Nodes() store.NodeRepo { return dao14d1Nodes{s.Store.Nodes(), s} }

type dao14d1Prefixes struct {
	store.PrefixRepo
	s *dao14d1Store
}

func (s *dao14d1Store) Prefixes() store.PrefixRepo { return dao14d1Prefixes{s.Store.Prefixes(), s} }

type dao14d1ThresholdTemplates struct {
	store.ThresholdTemplateRepo
	s *dao14d1Store
}

func (s *dao14d1Store) ThresholdTemplates() store.ThresholdTemplateRepo {
	return dao14d1ThresholdTemplates{s.Store.ThresholdTemplates(), s}
}

type dao14d1Thresholds struct {
	store.ThresholdRepo
	s *dao14d1Store
}

func (s *dao14d1Store) Thresholds() store.ThresholdRepo {
	return dao14d1Thresholds{s.Store.Thresholds(), s}
}

type dao14d1Responses struct {
	store.ResponseRepo
	s *dao14d1Store
}

func (s *dao14d1Store) Responses() store.ResponseRepo {
	return dao14d1Responses{s.Store.Responses(), s}
}

type dao14d1XDropTargets struct {
	store.XDropTargetRepo
	s *dao14d1Store
}

func (s *dao14d1Store) XDropTargets() store.XDropTargetRepo {
	return dao14d1XDropTargets{s.Store.XDropTargets(), s}
}

type dao14d1Preconditions struct {
	store.PreconditionRepo
	s *dao14d1Store
}

func (s *dao14d1Store) Preconditions() store.PreconditionRepo {
	return dao14d1Preconditions{s.Store.Preconditions(), s}
}

type dao14d1Attacks struct {
	store.AttackRepo
	s *dao14d1Store
}

func (s *dao14d1Store) Attacks() store.AttackRepo { return dao14d1Attacks{s.Store.Attacks(), s} }

type dao14d1AuditLog struct {
	store.AuditLogRepo
	s *dao14d1Store
}

func (s *dao14d1Store) AuditLog() store.AuditLogRepo { return dao14d1AuditLog{s.Store.AuditLog(), s} }

type dao14d1Stats struct {
	store.StatsRepo
	s *dao14d1Store
}

func (s *dao14d1Store) Stats() store.StatsRepo { return dao14d1Stats{s.Store.Stats(), s} }

type dao14d1ScheduledActions struct {
	store.ScheduledActionRepo
	s *dao14d1Store
}

func (s *dao14d1Store) ScheduledActions() store.ScheduledActionRepo {
	return dao14d1ScheduledActions{s.Store.ScheduledActions(), s}
}

type dao14d1ActionExecLog struct {
	store.ActionExecLogRepo
	s *dao14d1Store
}

func (s *dao14d1Store) ActionExecLog() store.ActionExecLogRepo {
	return dao14d1ActionExecLog{s.Store.ActionExecLog(), s}
}

type dao14d1XDropConnectors struct {
	store.XDropConnectorRepo
	s *dao14d1Store
}

func (s *dao14d1Store) XDropConnectors() store.XDropConnectorRepo {
	return dao14d1XDropConnectors{s.Store.XDropConnectors(), s}
}

type dao14d1FlowListeners struct {
	store.FlowListenerRepo
	s *dao14d1Store
}

func (s *dao14d1Store) FlowListeners() store.FlowListenerRepo {
	return dao14d1FlowListeners{s.Store.FlowListeners(), s}
}

type dao14d1FlowSources struct {
	store.FlowSourceRepo
	s *dao14d1Store
}

func (s *dao14d1Store) FlowSources() store.FlowSourceRepo {
	return dao14d1FlowSources{s.Store.FlowSources(), s}
}

func (r dao14d1Users) Get(c context.Context, id int) (*store.User, error) {
	user, err := r.UserRepo.Get(c, id)
	if user != nil && r.s.viewer {
		copy := *user
		copy.Role = "viewer"
		user = &copy
	}
	return user, err
}
func (r dao14d1Users) List(context.Context) ([]store.User, error) {
	return nil, r.s.hit("Users.List", false)
}
func (r dao14d1Users) Create(context.Context, *store.User) (int, error) {
	return 40, r.s.hit("Users.Create", true)
}
func (r dao14d1Nodes) Create(context.Context, *store.Node) error {
	return r.s.hit("Nodes.Create", true)
}
func (r dao14d1Nodes) List(context.Context) ([]store.Node, error) {
	return []store.Node{{ID: "n1", Enabled: true, Mode: "flow"}}, r.s.hit("Nodes.List", false)
}
func (r dao14d1Nodes) Get(context.Context, string) (*store.Node, error) {
	return &store.Node{ID: "n1", Mode: "flow", Enabled: true}, nil
}
func (r dao14d1Nodes) UpdateDeliveryVersionCurrent(context.Context, string, int64) error {
	r.s.versions++
	return nil
}
func (r dao14d1Prefixes) List(context.Context) ([]store.WatchPrefix, error) {
	var rows []store.WatchPrefix
	for _, p := range r.s.prefixes {
		rows = append(rows, p)
	}
	return rows, r.s.hit("Prefixes.List", false)
}
func (r dao14d1Prefixes) ListTree(c context.Context) ([]store.WatchPrefix, error) {
	if err := r.s.hit("Prefixes.ListTree", false); err != nil {
		return nil, err
	}
	return r.List(c)
}
func (r dao14d1Prefixes) Count(context.Context) (int, error) {
	return len(r.s.prefixes), r.s.hit("Prefixes.Count", false)
}
func (r dao14d1Prefixes) Get(_ context.Context, id int) (*store.WatchPrefix, error) {
	if row, ok := r.s.prefixes[id]; ok {
		return &row, nil
	}
	return nil, pgx.ErrNoRows
}
func (r dao14d1Prefixes) Create(_ context.Context, row *store.WatchPrefix) (int, error) {
	err := r.s.hit("Prefixes.Create", true)
	if err == nil {
		copy := *row
		copy.ID = 40
		r.s.prefixes[40] = copy
	}
	return 40, err
}
func (r dao14d1Prefixes) Update(_ context.Context, row *store.WatchPrefix) error {
	err := r.s.hit("Prefixes.Update", true)
	if err == nil {
		r.s.prefixes[row.ID] = *row
	}
	return err
}
func (r dao14d1ThresholdTemplates) Get(_ context.Context, id int) (*store.ThresholdTemplate, error) {
	if err := r.s.hit("Templates.Get", false); err != nil {
		return nil, err
	}
	if row, ok := r.s.templates[id]; ok {
		return &row, nil
	}
	return nil, fmt.Errorf("template %d: %w", id, pgx.ErrNoRows)
}
func (r dao14d1ThresholdTemplates) List(context.Context) ([]store.ThresholdTemplate, error) {
	var rows []store.ThresholdTemplate
	for _, row := range r.s.templates {
		rows = append(rows, row)
	}
	return rows, nil
}
func (r dao14d1ThresholdTemplates) Create(context.Context, *store.ThresholdTemplate) (int, error) {
	return 40, r.s.hit("Templates.Create", true)
}
func (r dao14d1ThresholdTemplates) Update(_ context.Context, row *store.ThresholdTemplate) error {
	err := r.s.hit("Templates.Update", true)
	if err == nil {
		copy := *row
		r.s.templateUpdate = &copy
	}
	return err
}
func (r dao14d1ThresholdTemplates) Delete(context.Context, int) error {
	return r.s.hit("Templates.Delete", true)
}
func (r dao14d1ThresholdTemplates) Duplicate(_ context.Context, _ int, name string) (int, error) {
	r.s.duplicateName = name
	return 40, r.s.hit("Templates.Duplicate", true)
}
func (r dao14d1ThresholdTemplates) ListRules(_ context.Context, id int) ([]store.Threshold, error) {
	return r.s.rules[id], r.s.hit("Templates.ListRules", false)
}
func (r dao14d1ThresholdTemplates) ListPrefixesUsing(context.Context, int) ([]store.WatchPrefix, error) {
	return nil, nil
}
func (r dao14d1Thresholds) List(context.Context) ([]store.Threshold, error) {
	var rows []store.Threshold
	for _, row := range r.s.thresholds {
		rows = append(rows, *row)
	}
	return rows, r.s.hit("Thresholds.List", false)
}
func (r dao14d1Thresholds) Count(context.Context) (int, error) {
	return len(r.s.thresholds), r.s.hit("Thresholds.Count", false)
}
func (r dao14d1Thresholds) Get(_ context.Context, id int) (*store.Threshold, error) {
	if row, ok := r.s.thresholds[id]; ok {
		return row, nil
	}
	return nil, pgx.ErrNoRows
}
func (r dao14d1Thresholds) Create(context.Context, *store.Threshold) (int, error) {
	return 40, r.s.hit("Thresholds.Create", true)
}
func (r dao14d1Thresholds) Update(_ context.Context, row *store.Threshold) error {
	err := r.s.hit("Thresholds.Update", true)
	if err == nil {
		copy := dao12aCopy(*row)
		r.s.thresholdUpdate = &copy
	}
	return err
}
func (r dao14d1Responses) Get(_ context.Context, id int) (*store.Response, error) {
	if row, ok := r.s.responses[id]; ok {
		return &row, nil
	}
	return nil, pgx.ErrNoRows
}
func (r dao14d1Responses) Update(_ context.Context, row *store.Response) error {
	err := r.s.hit("Responses.Update", true)
	if err == nil {
		copy := *row
		r.s.responseUpdate = &copy
	}
	return err
}
func (r dao14d1Responses) ListActions(_ context.Context, id int) ([]store.ResponseAction, error) {
	return r.s.responseActions[id], r.s.hit("Responses.ListActions", false)
}
func (r dao14d1Responses) GetAction(_ context.Context, id int) (*store.ResponseAction, error) {
	r.s.sequence = append(r.s.sequence, "GetAction")
	if err := r.s.hit("Responses.GetAction", false); err != nil {
		return nil, err
	}
	if row, ok := r.s.actions[id]; ok {
		return &row, nil
	}
	return nil, pgx.ErrNoRows
}
func (r dao14d1Responses) CreateAction(_ context.Context, row *store.ResponseAction) (int, error) {
	err := r.s.hit("Responses.CreateAction", true)
	if err == nil {
		copy := *row
		copy.ID = 40
		r.s.actions[40] = copy
	}
	return 40, err
}
func (r dao14d1Responses) UpdateAction(_ context.Context, row *store.ResponseAction) error {
	err := r.s.hit("Responses.UpdateAction", true)
	if err == nil {
		r.s.actions[row.ID] = dao12aCopy(*row)
	}
	return err
}
func (r dao14d1Responses) DeleteAction(_ context.Context, id int) error {
	delete(r.s.actions, id)
	return r.s.hit("Responses.DeleteAction", true)
}
func (r dao14d1XDropTargets) List(context.Context, int) ([]store.XDropConnector, error) {
	return []store.XDropConnector{{ID: 3, Enabled: true}}, nil
}
func (r dao14d1XDropTargets) Set(context.Context, int, []int) error {
	return r.s.hit("Targets.Set", true)
}
func (r dao14d1Preconditions) ReplaceAll(context.Context, int, []store.ActionPrecondition) error {
	return r.s.hit("Preconditions.ReplaceAll", true)
}
func (r dao14d1Attacks) List(context.Context, store.AttackFilter) ([]store.Attack, error) {
	return nil, r.s.hit("Attacks.List", false)
}
func (r dao14d1Attacks) CountActive(context.Context) (int, error) {
	return 0, r.s.hit("Attacks.CountActive", false)
}
func (r dao14d1AuditLog) List(context.Context, store.AuditFilter) ([]store.AuditLog, error) {
	return nil, r.s.hit("Audit.List", false)
}
func (r dao14d1AuditLog) Create(_ context.Context, row *store.AuditLog) error {
	r.s.sequence = append(r.s.sequence, "Audit")
	r.s.audits++
	copy := dao12aCopy(*row)
	r.s.audit = &copy
	return nil
}
func (r dao14d1Stats) QueryTotalTimeseries(context.Context, store.TimeseriesFilter) ([]store.TimeseriesPoint, error) {
	return nil, r.s.hit("Stats.Total", false)
}
func (r dao14d1ScheduledActions) CancelByBusinessKey(context.Context, string, int, int, int, string, string) error {
	r.s.sequence = append(r.s.sequence, "Cancel")
	return nil
}
func (r dao14d1ActionExecLog) Create(_ context.Context, row *store.ActionExecutionLog) (int, error) {
	r.s.sequence = append(r.s.sequence, "ExecLog")
	if row.Status != "failed" || row.ErrorMessage == "" {
		return 0, errors.New("fixture expected failed execution details")
	}
	return 40, r.s.hit("ExecLog.Create", true)
}
func (r dao14d1XDropConnectors) ListEnabled(context.Context) ([]store.XDropConnector, error) {
	return nil, nil
}
func (r dao14d1FlowListeners) Get(context.Context, int) (*store.FlowListener, error) {
	return &store.FlowListener{ID: 1, NodeID: "n1", ListenAddress: ":6343", ProtocolMode: "sflow", Enabled: true}, nil
}
func (r dao14d1FlowListeners) Create(_ context.Context, row *store.FlowListener) (int, error) {
	copy := *row
	r.s.listenerWrite = &copy
	return 40, r.s.hit("Listeners.Create", true)
}
func (r dao14d1FlowListeners) Update(_ context.Context, row *store.FlowListener) error {
	copy := *row
	r.s.listenerWrite = &copy
	return r.s.hit("Listeners.Update", true)
}
func (r dao14d1FlowSources) Get(context.Context, int) (*store.FlowSource, error) {
	return &store.FlowSource{ID: 1, ListenerID: 1, Name: "s", DeviceIP: "192.0.2.1", SampleMode: "none", Enabled: true}, nil
}
func (r dao14d1FlowSources) Create(_ context.Context, row *store.FlowSource) (int, error) {
	copy := *row
	r.s.sourceWrite = &copy
	return 40, r.s.hit("Sources.Create", true)
}
func (r dao14d1FlowSources) Update(_ context.Context, row *store.FlowSource) error {
	copy := *row
	r.s.sourceWrite = &copy
	return r.s.hit("Sources.Update", true)
}

func dao14d1Request(t *testing.T, s *dao14d1Store, method, path string, body io.Reader) (*httptest.ResponseRecorder, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	deps := api.Dependencies{Store: s, JWTSecret: testJWTSecret, NodeState: ingestion.NewNodeState(), ActionEngine: action.NewEngine(s, "auto")}
	deps.Tracker = tracker.New(tracker.Config{}, s, nil, nil, nil)
	deps.ConfigPub = configpub.New(s, s, func() []string { return []string{"n1"} })
	var capture bytes.Buffer
	old := log.Writer()
	log.SetOutput(&capture)
	defer log.SetOutput(old)
	rec := httptest.NewRecorder()
	api.NewRouter(deps).ServeHTTP(rec, req)
	return rec, capture.String()
}

func dao14d1Error(t *testing.T, w *httptest.ResponseRecorder, logs string, status int, message string, seed error) {
	t.Helper()
	if w.Code != status {
		t.Errorf("status=%d want=%d body=%s", w.Code, status, w.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response JSON: %v; body=%s", err, w.Body)
	}
	if !reflect.DeepEqual(body, map[string]any{"error": message}) {
		t.Errorf("body=%v want error=%q", body, message)
	}
	forbidden := []string{"SQLSTATE", "ERROR:", "relation", "violates", "MARKERUSER", "user=", "database="}
	var pgErr *pgconn.PgError
	if errors.As(seed, &pgErr) && pgErr.ConstraintName != "" {
		forbidden = append(forbidden, pgErr.ConstraintName)
	}
	for _, word := range forbidden {
		if strings.Contains(w.Body.String(), word) {
			t.Errorf("body contains %q: %s", word, w.Body)
		}
	}
	if status >= 400 && status < 500 && strings.TrimSpace(logs) != "" {
		t.Errorf("4xx must not log: %s", logs)
	}
	if status >= 500 && seed != nil && !strings.Contains(logs, seed.Error()) {
		t.Errorf("missing original error %q in logs: %s", seed, logs)
	}
}
func dao14d1NoWrites(t *testing.T, s *dao14d1Store, want ...string) {
	t.Helper()
	if !slices.Equal(s.writes, want) || s.audits != 0 || s.pushes != 0 || s.versions != 0 {
		t.Errorf("writes=%v want=%v audits=%d pushes=%d versions=%d", s.writes, want, s.audits, s.pushes, s.versions)
	}
}
func dao14d1PG(code, constraint string) error {
	message := "MARKER invalid input syntax"
	table := map[string]string{
		"watch_prefixes_threshold_template_id_fkey":       "watch_prefixes",
		"threshold_templates_response_id_fkey":            "threshold_templates",
		"thresholds_template_id_fkey":                     "thresholds",
		"thresholds_owner_xor":                            "thresholds",
		"response_action_xdrop_targets_connector_id_fkey": "response_action_xdrop_targets",
		"response_action_xdrop_targets_action_id_fkey":    "response_action_xdrop_targets",
		"action_preconditions_action_id_fkey":             "action_preconditions",
	}[constraint]
	if table == "" {
		table = "MARKER_table"
	}
	switch code {
	case "23505":
		message = fmt.Sprintf("duplicate key value violates unique constraint %q", constraint)
	case "23503":
		message = fmt.Sprintf("insert or update on table %q violates foreign key constraint %q", table, constraint)
	case "23514":
		message = fmt.Sprintf("new row for relation %q violates check constraint %q", table, constraint)
	case "23502":
		message = "null value in column MARKER_column of relation MARKER_table violates not-null constraint"
	case "2201X":
		message = "OFFSET must not be negative"
	case "42P01":
		message = "relation MARKER_table does not exist"
	case "22003":
		message = "integer out of range"
	}
	return fmt.Errorf("fixture repository: %w", &pgconn.PgError{Severity: "ERROR", Code: code, Message: message, ConstraintName: constraint})
}

// Use pgconn's real connection-error path while the injected dialer guarantees
// that this test never opens a socket or performs DNS/network I/O.
func dao14d1ConnectError(t *testing.T) error {
	t.Helper()
	cfg, err := pgconn.ParseConfig("host=127.0.0.1 port=1 user=MARKERUSER dbname=MARKERDB sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	cfg.DialFunc = func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED }
	_, err = pgconn.ConnectConfig(context.Background(), cfg)
	var connect *pgconn.ConnectError
	if !errors.As(err, &connect) {
		t.Fatalf("fixture did not produce ConnectError: %T %v", err, err)
	}
	return fmt.Errorf("fixture repository: %w", err)
}

func TestDao14d1_G1(t *testing.T) {
	const thresholdBody = `{"domain":"subnet","direction":"receives","decoder":"ip","unit":"pps","comparison":"over","value":1000}`
	const prefixThresholdBody = `{"prefix_id":1,"domain":"subnet","direction":"receives","decoder":"ip","unit":"pps","comparison":"over","value":1000}`
	const ruleBody = `{"decoder":"ip","unit":"pps","value":1000,"domain":"subnet"}`
	for _, tc := range []struct {
		name, method, path, body, key, code, constraint, message string
		status                                                   int
	}{
		{"U2", "POST", "/api/users", `{"username":"dao14u","password":"dao14-pass-1"}`, "Users.Create", "23505", "users_username_key", "already exists", 409},
		{"N2", "POST", "/api/nodes", `{"id":"dao14-n1","api_key":"k1"}`, "Nodes.Create", "23505", "nodes_pkey", "already exists", 409},
		{"P2_Syntax", "POST", "/api/prefixes", `{"prefix":"abc"}`, "Prefixes.Create", "22P02", "", "invalid input", 400},
		{"P2_HostBits", "POST", "/api/prefixes", `{"prefix":"192.0.2.1/24"}`, "Prefixes.Create", "22P02", "", "invalid input", 400},
		{"P2_TemplateFK", "POST", "/api/prefixes", `{"prefix":"198.51.100.0/24","threshold_template_id":99999}`, "Prefixes.Create", "23503", "watch_prefixes_threshold_template_id_fkey", "referenced object not found", 400},
		{"P4_UpdateFK", "PUT", "/api/prefixes/1", `{"threshold_template_id":99999}`, "Prefixes.Update", "23503", "watch_prefixes_threshold_template_id_fkey", "referenced object not found", 400},
		{"T2", "POST", "/api/threshold-templates", `{"name":"dao14-t2","response_id":99999}`, "Templates.Create", "23503", "threshold_templates_response_id_fkey", "referenced object not found", 400},
		{"T6", "POST", "/api/threshold-templates/1/duplicate", "", "Templates.Duplicate", "23505", "threshold_templates_name_key", "already exists", 409},
		{"T8_FK", "POST", "/api/threshold-templates/99999/rules", ruleBody, "Thresholds.Create", "23503", "thresholds_template_id_fkey", "referenced object not found", 400},
		{"T8_Dup", "POST", "/api/threshold-templates/1/rules", ruleBody, "Thresholds.Create", "23505", "idx_thresholds_template_key", "already exists", 409},
		{"H2_XOR", "POST", "/api/thresholds", thresholdBody, "Thresholds.Create", "23514", "thresholds_owner_xor", "invalid value", 400},
		{"H2_Dup", "POST", "/api/thresholds", prefixThresholdBody, "Thresholds.Create", "23505", "idx_thresholds_prefix_key", "already exists", 409},
		{"H4", "PUT", "/api/thresholds/22", `{"value":2000}`, "Thresholds.Update", "23505", "idx_thresholds_prefix_key", "already exists", 409},
		{"H6", "PUT", "/api/threshold-rules/23", `{"value":2000}`, "Thresholds.Update", "23514", "thresholds_owner_xor", "invalid value", 400},
		{"AC2", "POST", "/api/responses/1/actions", "", "Targets.Set", "23503", "response_action_xdrop_targets_connector_id_fkey", "set xdrop targets: referenced object not found", 400},
		{"AC3", "PUT", "/api/actions/10", `{"target_node_ids":[99999]}`, "Targets.Set", "23503", "response_action_xdrop_targets_connector_id_fkey", "set xdrop targets: database error", 500},
		{"AC6_Conn", "PUT", "/api/actions/34/xdrop-targets", `{"connector_ids":[99999]}`, "Targets.Set", "23503", "response_action_xdrop_targets_connector_id_fkey", "referenced object not found", 400},
		{"AC6_Action", "PUT", "/api/actions/99999/xdrop-targets", `{"connector_ids":[3]}`, "Targets.Set", "23503", "response_action_xdrop_targets_action_id_fkey", "referenced object not found", 400},
		{"AC8", "PUT", "/api/actions/99999/preconditions", `{"preconditions":[{"attribute":"pps","operator":"gt","value":"1"}]}`, "Preconditions.ReplaceAll", "23503", "action_preconditions_action_id_fkey", "referenced object not found", 400},
		{"K1", "GET", "/api/attacks?offset=-1", "", "Attacks.List", "2201X", "", "invalid input", 400},
		{"K1_Audit", "GET", "/api/audit-log?offset=-1", "", "Audit.List", "2201X", "", "invalid input", 400},
		{"U2_NotNull", "POST", "/api/users", `{"username":"dao14u","password":"dao14-pass-1"}`, "Users.Create", "23502", "", "invalid value", 400},
		{"DeleteInUse", "DELETE", "/api/threshold-templates/5", "", "Templates.Delete", "23503", "watch_prefixes_threshold_template_id_fkey", "in use", 409},
		{"B4_Create", "POST", "/api/thresholds", prefixThresholdBody, "Prefixes.List", "", "", "validation lookup failed: database error", 500},
		{"B4_Update", "PUT", "/api/thresholds/22", `{"value":2000}`, "Prefixes.List", "", "", "validation lookup failed: database error", 500},
		{"B4_Rule", "POST", "/api/threshold-templates/1/rules", ruleBody, "Prefixes.List", "", "", "validation lookup failed: database error", 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dao14d1Fixture()
			seed := dao14d1PG(tc.code, tc.constraint)
			if tc.name == "P2_Syntax" || tc.name == "P2_HostBits" {
				message := "invalid input syntax for type cidr: " + strconv.Quote("abc")
				if tc.name == "P2_HostBits" {
					message = "invalid cidr value: " + strconv.Quote("192.0.2.1/24")
				}
				seed = fmt.Errorf("fixture repository: %w", &pgconn.PgError{Severity: "ERROR", Code: "22P02", Message: message})
			}
			if tc.code == "" {
				seed = errors.New("MARKER-b4 user=x database=y")
			}
			s.faults[tc.key] = seed
			body := tc.body
			if tc.name == "AC2" {
				object := dao12aBody("xdrop")
				object["target_node_ids"] = []int{99999}
				raw, err := json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
				body = string(raw)
			}
			if tc.method == "GET" {
				s.viewer = true
			}
			before := dao12aCopy(s.actions[10])
			w, logs := dao14d1Request(t, s, tc.method, tc.path, strings.NewReader(body))
			dao14d1Error(t, w, logs, tc.status, tc.message, seed)
			if s.calls[tc.key] != 1 {
				t.Errorf("injection %s reached %d times, want 1", tc.key, s.calls[tc.key])
			}
			switch tc.name {
			case "AC2":
				dao14d1NoWrites(t, s, "Responses.CreateAction", "Targets.Set", "Responses.DeleteAction")
				if s.calls["Responses.DeleteAction"] != 1 {
					t.Error("missing create rollback")
				}
			case "AC3":
				dao14d1NoWrites(t, s, "Responses.UpdateAction", "Targets.Set", "Responses.UpdateAction")
				if !reflect.DeepEqual(s.actions[10], before) {
					t.Error("parent row was not restored")
				}
			default:
				if strings.HasPrefix(tc.name, "B4_") || tc.method == "GET" {
					dao14d1NoWrites(t, s)
				} else {
					dao14d1NoWrites(t, s, tc.key)
				}
			}
		})
	}
	t.Run("B4Chain", dao14d1B4Chain)
	t.Run("B4ResponseLookup", dao14d1B4ResponseLookup)
}

func dao14d1B4Chain(t *testing.T) {
	for _, tc := range []struct{ name, method, path, body string }{
		{"Create", "POST", "/api/thresholds", `{"prefix_id":1,"domain":"subnet","direction":"receives","decoder":"ip","unit":"pps","comparison":"over","value":1000}`},
		{"Update", "PUT", "/api/thresholds/22", `{"value":2000}`},
		{"Rule", "POST", "/api/threshold-templates/1/rules", `{"decoder":"ip","unit":"pps","value":1000,"domain":"subnet"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dao14d1Fixture()
			seed := fmt.Errorf("prefix repository: %w", &pgconn.PgError{
				Severity: "ERROR", Code: "23505", ConstraintName: "dao14d1_chain_key",
				Message: `duplicate key value violates unique constraint "dao14d1_chain_key"`,
			})
			s.faults["Prefixes.List"] = seed
			w, logs := dao14d1Request(t, s, tc.method, tc.path, strings.NewReader(tc.body))
			dao14d1Error(t, w, logs, 409, "validation lookup failed: already exists", seed)
			if s.calls["Prefixes.List"] != 1 {
				t.Errorf("Prefixes.List calls=%d, want 1", s.calls["Prefixes.List"])
			}
			dao14d1NoWrites(t, s)
		})
	}
}

func dao14d1B4ResponseLookup(t *testing.T) {
	for _, tc := range []struct{ name, prefix, body string }{
		{"Global", "0.0.0.0/0", `{"prefix_id":1,"domain":"subnet","direction":"receives","decoder":"ip","unit":"pps","comparison":"over","value":1000,"response_id":1}`},
		{"Sends", "192.0.2.0/24", `{"prefix_id":1,"domain":"subnet","direction":"sends","decoder":"ip","unit":"pps","comparison":"over","value":1000,"response_id":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dao14d1Fixture()
			s.prefixes[1] = store.WatchPrefix{ID: 1, Prefix: tc.prefix, Enabled: true}
			seed := errors.New("MARKER-response-lookup user=dao14 database=dao14")
			s.faults["Responses.ListActions"] = seed
			w, logs := dao14d1Request(t, s, "POST", "/api/thresholds", strings.NewReader(tc.body))
			dao14d1Error(t, w, logs, 500, "validation lookup failed: database error", seed)
			if strings.Contains(w.Body.String(), seed.Error()) {
				t.Errorf("response exposed lookup error: %s", w.Body)
			}
			if strings.Count(logs, "ERROR api:") != 1 {
				t.Errorf("want exactly one ERROR api log, got %q", logs)
			}
			if s.calls["Prefixes.List"] != 1 || s.calls["Responses.ListActions"] != 1 {
				t.Errorf("lookup calls: Prefixes.List=%d Responses.ListActions=%d, want 1 each", s.calls["Prefixes.List"], s.calls["Responses.ListActions"])
			}
			dao14d1NoWrites(t, s)
		})
	}
}

func TestDao14d1_G2(t *testing.T) {
	marker := errors.New("MARKER-dbdown user=dao14 database=dao14")
	for _, tc := range []struct{ name, path, key, message string }{
		{"Users", "/api/users", "Users.List", "database error"},
		{"Attacks", "/api/attacks", "Attacks.List", "database error"},
		{"Summary/attacks", "/api/stats/summary", "Attacks.CountActive", "stats summary: attacks: database error"},
		{"Summary/nodes", "/api/stats/summary", "Nodes.List", "stats summary: nodes: database error"},
		{"Summary/prefixes", "/api/stats/summary", "Prefixes.Count", "stats summary: prefixes: database error"},
		{"Summary/thresholds", "/api/stats/summary", "Thresholds.Count", "stats summary: thresholds: database error"},
		{"ConnectError", "/api/prefixes", "Prefixes.ListTree", "database error"},
		{"SummaryAlways500", "/api/stats/summary", "Attacks.CountActive", "stats summary: attacks: database error"},
		{"Sys500/22003", "/api/stats/total-timeseries?resolution=5s", "Stats.Total", "database error"},
		{"Sys500/40001", "/api/stats/total-timeseries?resolution=5s", "Stats.Total", "database error"},
		{"Sys500/57014", "/api/stats/total-timeseries?resolution=5s", "Stats.Total", "database error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dao14d1Fixture()
			seed := marker
			if tc.name == "ConnectError" {
				seed = dao14d1ConnectError(t)
			}
			if tc.name == "SummaryAlways500" {
				seed = dao14d1PG("22P02", "")
			}
			if strings.HasPrefix(tc.name, "Sys500/") {
				seed = dao14d1PG(strings.TrimPrefix(tc.name, "Sys500/"), "")
			}
			if tc.name == "Attacks" {
				s.viewer = true
			}
			s.faults[tc.key] = seed
			w, logs := dao14d1Request(t, s, "GET", tc.path, nil)
			dao14d1Error(t, w, logs, 500, tc.message, seed)
			dao14d1NoWrites(t, s)
			if s.calls[tc.key] != 1 {
				t.Errorf("injection reached %d times, want 1", s.calls[tc.key])
			}
			if tc.name == "Users" {
				if strings.Count(strings.TrimSpace(logs), "\n") != 0 || !strings.Contains(logs, "ERROR api: GET /api/users: ") {
					t.Errorf("want one contextual error log: %q", logs)
				}
			}
		})
	}
	for _, kind := range []string{"DB", "DBConnectError", "DB42P01", "DBNoRows", "Upstream"} {
		for _, failLog := range []bool{false, true} {
			branch := "ExecLogOK"
			if failLog {
				branch = "ExecLogFail"
			}
			t.Run("ForceRemove/"+kind+"/"+branch, func(t *testing.T) {
				s := dao14d1Fixture()
				seed := errors.New("MARKER-db user=x database=y")
				switch kind {
				case "DBConnectError":
					seed = dao14d1ConnectError(t)
				case "DB42P01":
					seed = dao14d1PG("42P01", "")
				case "DBNoRows":
					seed = fmt.Errorf("response_action 10: %w", pgx.ErrNoRows)
				case "Upstream":
					seed = errors.New("xdrop connector 7 not found or disabled")
				}
				if kind != "Upstream" {
					s.faults["Responses.GetAction"] = seed
				}
				if failLog {
					s.faults["ExecLog.Create"] = errors.New("MARKER-exec-log")
				}
				w, logs := dao14d1Request(t, s, "POST", "/api/active-actions/force-remove", strings.NewReader(`{"attack_id":20,"action_id":10,"connector_id":7,"external_rule_id":"rule-1"}`))
				dao14d1Error(t, w, logs, 500, "force remove failed", seed)
				want := []string{"Cancel", "Cancel", "GetAction", "ExecLog"}
				if !failLog {
					want = append(want, "Audit")
				}
				if !slices.Equal(s.sequence, want) {
					t.Errorf("sequence=%v want=%v", s.sequence, want)
				}
				if !slices.Equal(s.writes, []string{"ExecLog.Create"}) {
					t.Errorf("unexpected writes=%v", s.writes)
				}
				if failLog && (s.audits != 0 || s.pushes != 0) {
					t.Errorf("failed execution log published: audits=%d pushes=%d", s.audits, s.pushes)
				}
				if !failLog && (s.audits != 1 || s.pushes != 1) {
					t.Errorf("missing publication: audits=%d pushes=%d", s.audits, s.pushes)
				}
			})
		}
	}
}

func TestDao14d1_G5(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantName, wantDescription string
		enabled                               bool
		status                                int
	}{
		{"EnabledOnly", `{"enabled":false}`, "r-old", "d-old", false, 200},
		{"NameOnly", `{"name":"r2"}`, "r2", "d-old", true, 200},
		{"DescNull", `{"description":null}`, "r-old", "d-old", true, 200},
		{"ExplicitEmptyDescription", `{"name":"r3","description":""}`, "r3", "", true, 200},
		{"ExtraFieldIgnored", `{"name":"r2","description":"d2","created_at":"garbage","action_count":"x","id":"y"}`, "r2", "d2", true, 200},
		{"EmptyName", `{"name":""}`, "", "", false, 400},
		{"NullName", `{"name":null,"enabled":false}`, "r-old", "d-old", false, 200},
		{"AuditDiff", `{"enabled":false}`, "r-old", "d-old", false, 200},
		{"AuditDiffEmptyObject", `{}`, "r-old", "d-old", true, 200},
		{"AuditDiffNameNull", `{"name":null}`, "r-old", "d-old", true, 200},
		{"AuditDiffDescriptionNull", `{"description":null}`, "r-old", "d-old", true, 200},
		{"AuditDiffEnabledNull", `{"enabled":null}`, "r-old", "d-old", true, 200},
		{"NotFound", `{"enabled":false}`, "", "", false, 404},
		{"DupEnabledNull", `{"name":"r-old","description":"d-old","enabled":false,"enabled":null}`, "r-old", "d-old", true, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dao14d1Fixture()
			path := "/api/responses/1"
			if tc.name == "NotFound" {
				path = "/api/responses/99999"
			}
			w, logs := dao14d1Request(t, s, "PUT", path, strings.NewReader(tc.body))
			if tc.status >= 400 {
				message := "name is required"
				if tc.status == 404 {
					message = "response not found"
				}
				dao14d1Error(t, w, logs, tc.status, message, nil)
				dao14d1NoWrites(t, s)
				return
			}
			if w.Code != 200 {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			got := s.responseUpdate
			if got == nil || got.ID != 1 || got.Name != tc.wantName || got.Description != tc.wantDescription || got.Enabled != tc.enabled {
				t.Errorf("updated=%+v want name=%q description=%q enabled=%v", got, tc.wantName, tc.wantDescription, tc.enabled)
			}
			if s.calls["Responses.Update"] != 1 || s.audits != 1 || s.pushes != 1 {
				t.Errorf("update=%d audits=%d pushes=%d", s.calls["Responses.Update"], s.audits, s.pushes)
			}
			if strings.HasPrefix(tc.name, "AuditDiff") {
				var diff struct{ New store.Response }
				if s.audit == nil {
					t.Fatal("missing audit")
				}
				if err := json.Unmarshal(s.audit.Diff, &diff); err != nil {
					t.Fatal(err)
				}
				if diff.New.ID != 1 || diff.New.Name != "r-old" || diff.New.Description != "d-old" {
					t.Errorf("audit new: id=%d name=%q description=%q; want id=1 name=\"r-old\" description=\"d-old\"", diff.New.ID, diff.New.Name, diff.New.Description)
				}
			}
		})
	}
}

type dao14d1BrokenBody struct{ sent bool }

func (r *dao14d1BrokenBody) Read(p []byte) (int, error) {
	if r.sent {
		return 0, errors.New("MARKER-body-read")
	}
	r.sent = true
	return copy(p, "{\"name\":\"x\"}"), nil
}
func TestDao14d1_G6(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"Garbage", "garbage", 400}, {"TypeMismatch", "{\"name\":1}", 400}, {"EmptyBody", "", 400},
		{"ClearResponse", "{\"response_id\":null}", 200}, {"NotFoundFirst", "garbage", 404},
		{"DupGarbage", "garbage", 400}, {"DupEmpty", "", 201}, {"DupEmptyObject", "{}", 201},
		{"DupNamed", "{\"name\":\"x\"}", 201}, {"GetRawDataError", "", 400}, {"NullBodyRegistered", "null", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dao14d1Fixture()
			row := s.templates[1]
			row.ResponseID = intPtr(7)
			s.templates[1] = row
			method, path := "PUT", "/api/threshold-templates/1"
			if strings.HasPrefix(tc.name, "Dup") {
				method, path = "POST", "/api/threshold-templates/1/duplicate"
			}
			if tc.name == "NotFoundFirst" {
				path = "/api/threshold-templates/99999"
			}
			var body io.Reader = strings.NewReader(tc.body)
			if tc.name == "GetRawDataError" {
				body = &dao14d1BrokenBody{}
			}
			w, logs := dao14d1Request(t, s, method, path, body)
			if w.Code != tc.status {
				t.Errorf("status=%d want=%d body=%s", w.Code, tc.status, w.Body)
			}
			if tc.status >= 400 {
				message := map[string]string{
					"Garbage":         "invalid character 'g' looking for beginning of value",
					"TypeMismatch":    "json: cannot unmarshal number into Go struct field ThresholdTemplate.name of type string",
					"EmptyBody":       "unexpected end of JSON input",
					"NotFoundFirst":   "template not found",
					"DupGarbage":      "invalid character 'g' looking for beginning of value",
					"GetRawDataError": "MARKER-body-read",
				}[tc.name]
				dao14d1Error(t, w, logs, tc.status, message, nil)
				dao14d1NoWrites(t, s)
				return
			}
			if method == "POST" {
				want := "t-old (Copy)"
				if tc.name == "DupNamed" {
					want = "x"
				}
				if s.calls["Templates.Duplicate"] != 1 || s.duplicateName != want {
					t.Errorf("duplicates=%d name=%q want=%q", s.calls["Templates.Duplicate"], s.duplicateName, want)
				}
			} else {
				if s.calls["Templates.Update"] != 1 || s.templateUpdate == nil {
					t.Fatal("missing update")
				}
				if tc.name == "ClearResponse" && s.templateUpdate.ResponseID != nil {
					t.Errorf("response_id was not cleared: %d", *s.templateUpdate.ResponseID)
				}
			}
			if s.audits != 1 || s.pushes != 1 {
				t.Errorf("audits=%d pushes=%d", s.audits, s.pushes)
			}
		})
	}
}

func TestDao14d1_G7(t *testing.T) {
	for _, tc := range []struct {
		name, path, body string
		template         bool
	}{
		{"PrefixRuleRehome", "/api/thresholds/22", "{\"template_id\":18,\"prefix_id\":null}", false},
		{"TemplateRuleRehome", "/api/threshold-rules/23", "{\"template_id\":null,\"prefix_id\":5}", true},
		{"TemplateRuleNumericRehome", "/api/threshold-rules/23", "{\"template_id\":19,\"prefix_id\":5}", true},
		{"TemplateRuleSingleFieldRehome", "/api/threshold-rules/23", "{\"template_id\":19}", true},
		{"PrefixRuleNumericRehome", "/api/thresholds/22", "{\"template_id\":18,\"prefix_id\":7}", false},
		{"ValueMerge", "/api/thresholds/22", "{\"value\":2000}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dao14d1Fixture()
			id := 22
			if tc.template {
				id = 23
			}
			old := s.thresholds[id]
			if tc.template {
				old.TemplateID = intPtr(18)
			} else {
				old.PrefixID = intPtr(22)
			}
			before := dao12aCopy(*old)
			w, _ := dao14d1Request(t, s, "PUT", tc.path, strings.NewReader(tc.body))
			if w.Code != 200 {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			want := dao12aCopy(before)
			if tc.name == "ValueMerge" {
				want.Value = 2000
			}
			if s.thresholdUpdate == nil || !reflect.DeepEqual(*s.thresholdUpdate, want) {
				t.Errorf("updated=%+v want=%+v", s.thresholdUpdate, want)
			}
			if !reflect.DeepEqual(*old, before) {
				t.Errorf("old row was mutated: %+v want=%+v", *old, before)
			}
			if s.calls["Thresholds.Update"] != 1 {
				t.Errorf("updates=%d", s.calls["Thresholds.Update"])
			}
		})
	}
}

func TestDao14d1_G9(t *testing.T) {
	for _, resource := range []string{"Listener", "Source"} {
		for _, variant := range []string{"Default", "Bogus", "PutMissing", "ExplicitEmpty", "ExplicitNull"} {
			t.Run(resource+variant, func(t *testing.T) {
				s := dao14d1Fixture()
				mode, route, key := "protocol_mode", "flow-listeners", "Listeners.Create"
				body := map[string]any{"node_id": "n1", "listen_address": ":6343"}
				if resource == "Source" {
					mode, route, key = "sample_mode", "flow-sources", "Sources.Create"
					body = map[string]any{"listener_id": 1, "name": "s", "device_ip": "192.0.2.1"}
				}
				method, path, status := "POST", "/api/"+route, 201
				switch variant {
				case "Bogus":
					body[mode] = "bogus"
					status = 400
				case "PutMissing":
					method = "PUT"
					path += "/1"
					status = 400
				case "ExplicitEmpty":
					body[mode] = ""
				case "ExplicitNull":
					body[mode] = nil
				}
				raw, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				w, logs := dao14d1Request(t, s, method, path, bytes.NewReader(raw))
				if status == 400 {
					message := "protocol_mode must be 'auto', 'sflow', 'netflow', or 'ipfix'"
					if resource == "Source" {
						message = "sample_mode must be 'auto', 'force', or 'none'"
					}
					dao14d1Error(t, w, logs, 400, message, nil)
					dao14d1NoWrites(t, s)
					return
				}
				if w.Code != 201 {
					t.Fatalf("status=%d body=%s", w.Code, w.Body)
				}
				if s.calls[key] != 1 {
					t.Errorf("create calls=%d", s.calls[key])
				}
				if resource == "Listener" {
					if s.listenerWrite == nil || s.listenerWrite.ProtocolMode != "auto" {
						t.Errorf("listener=%+v", s.listenerWrite)
					}
				} else if s.sourceWrite == nil || s.sourceWrite.SampleMode != "auto" {
					t.Errorf("source=%+v", s.sourceWrite)
				}
			})
		}
	}
}

func TestDao14d1_G11(t *testing.T) {
	const forbidden = "Global prefix (0.0.0.0/0) cannot use responses containing xDrop/BGP actions"
	for _, tc := range []struct {
		name, method, path, body string
		status                   int
		message, fault           string
		noGet                    bool
	}{
		{"CreateDefaultBGP", "POST", "/api/prefixes", "{\"prefix\":\"0.0.0.0/0\",\"threshold_template_id\":1}", 400, forbidden, "", false},
		{"CreateRuleXDrop", "POST", "/api/prefixes", "{\"prefix\":\"0.0.0.0/0\",\"threshold_template_id\":2}", 400, forbidden, "", false},
		{"UpdateRebind", "PUT", "/api/prefixes/3", "{\"threshold_template_id\":1}", 400, forbidden, "", false},
		{"UpdateToGlobal", "PUT", "/api/prefixes/1", "{\"prefix\":\"0.0.0.0/0\"}", 400, forbidden, "", false},
		{"UnrelatedEdit", "PUT", "/api/prefixes/2", "{\"name\":\"x\"}", 400, forbidden, "", false},
		{"TemplateMissing", "POST", "/api/prefixes", "{\"prefix\":\"0.0.0.0/0\",\"threshold_template_id\":99999}", 400, "threshold_template_id not found", "", false},
		{"LookupError", "POST", "/api/prefixes", "{\"prefix\":\"0.0.0.0/0\",\"threshold_template_id\":1}", 500, "failed to check template responses: database error", "Responses.ListActions", false},
		{"GetError", "POST", "/api/prefixes", "{\"prefix\":\"0.0.0.0/0\",\"threshold_template_id\":1}", 500, "failed to check template responses: database error", "Templates.Get", false},
		{"ListRulesError", "POST", "/api/prefixes", "{\"prefix\":\"0.0.0.0/0\",\"threshold_template_id\":1}", 500, "failed to check template responses: database error", "Templates.ListRules", false},
		{"NonGlobalSameTemplate", "POST", "/api/prefixes", "{\"prefix\":\"198.51.100.0/24\",\"threshold_template_id\":1}", 201, "", "", true},
		{"GlobalWebhookOnly", "POST", "/api/prefixes", "{\"prefix\":\"0.0.0.0/0\",\"threshold_template_id\":3}", 201, "", "", false},
		{"GlobalNoTemplate", "POST", "/api/prefixes", "{\"prefix\":\"0.0.0.0/0\"}", 201, "", "", true},
		{"Unbind", "PUT", "/api/prefixes/2", "{\"threshold_template_id\":null}", 200, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dao14d1Fixture()
			s.templates = map[int]store.ThresholdTemplate{1: {ID: 1, ResponseID: intPtr(1)}, 2: {ID: 2, ResponseID: intPtr(3)}, 3: {ID: 3, ResponseID: intPtr(3)}}
			s.rules = map[int][]store.Threshold{2: {{ResponseID: intPtr(2)}}, 3: {{ResponseID: intPtr(3)}}}
			s.responseActions = map[int][]store.ResponseAction{1: {{ActionType: store.ActionTypeBGP}}, 2: {{ActionType: store.ActionTypeXDrop}}, 3: {{ActionType: store.ActionTypeWebhook}}}
			s.prefixes = map[int]store.WatchPrefix{1: {ID: 1, Prefix: "192.0.2.0/24", ThresholdTemplateID: intPtr(1), Enabled: true}, 2: {ID: 2, Prefix: "0.0.0.0/0", ThresholdTemplateID: intPtr(1), Enabled: true}, 3: {ID: 3, Prefix: "0.0.0.0/0", Enabled: true}}
			var seed error
			if tc.fault != "" {
				seed = errors.New("MARKER-" + tc.fault + " user=x database=y")
				s.faults[tc.fault] = seed
			}
			w, logs := dao14d1Request(t, s, tc.method, tc.path, strings.NewReader(tc.body))
			if tc.status >= 400 {
				dao14d1Error(t, w, logs, tc.status, tc.message, seed)
				dao14d1NoWrites(t, s)
				if tc.fault != "" && s.calls[tc.fault] != 1 {
					t.Errorf("fault %s reached=%d", tc.fault, s.calls[tc.fault])
				}
				return
			}
			if w.Code != tc.status {
				t.Errorf("status=%d want=%d body=%s", w.Code, tc.status, w.Body)
			}
			if s.calls["Prefixes.Create"]+s.calls["Prefixes.Update"] != 1 || s.audits != 1 || s.pushes != 1 {
				t.Errorf("writes=%v audits=%d pushes=%d", s.writes, s.audits, s.pushes)
			}
			if tc.noGet && s.calls["Templates.Get"] != 0 {
				t.Errorf("unexpected template lookups=%d", s.calls["Templates.Get"])
			}
			if tc.name == "Unbind" && s.prefixes[2].ThresholdTemplateID != nil {
				t.Error("binding was not cleared")
			}
		})
	}
}

// TestDao14d1_G4Fixture checks the real-DB route fixture without a DB or listener.
func TestDao14d1_G4Fixture(t *testing.T) {
	s := NewMockStore()
	r := api.NewRouter(api.Dependencies{
		Store: s, APIKey: "dao14d1-key", JWTSecret: "dao14d1",
		ActionEngine: action.NewEngine(s, "auto"), Tracker: tracker.New(tracker.Config{}, s, nil, nil, nil),
		NodeState: ingestion.NewNodeState(), ThreshTree: threshold.NewTree(),
		ProfileEngine: baseline.NewProfileEngine(ring.New(ring.DefaultLimits()), s.DynDetect(), s.Stats()),
		BaselineCalc:  baseline.NewCalculator(s.Stats(), baseline.DefaultConfig()),
	})
	paths := map[string]string{
		"/api/users":                                "/api/users",
		"/api/nodes":                                "/api/nodes",
		"/api/nodes/:id":                            "/api/nodes/dao14-n1",
		"/api/nodes/:id/status":                     "/api/nodes/dao14-n1/status",
		"/api/prefixes":                             "/api/prefixes",
		"/api/prefixes/:id":                         "/api/prefixes/1",
		"/api/threshold-templates":                  "/api/threshold-templates",
		"/api/threshold-templates/:id":              "/api/threshold-templates/1",
		"/api/threshold-templates/:id/rules":        "/api/threshold-templates/1/rules",
		"/api/thresholds":                           "/api/thresholds?prefix_id=1",
		"/api/thresholds/:id":                       "/api/thresholds/1",
		"/api/responses":                            "/api/responses",
		"/api/responses/:id":                        "/api/responses/1",
		"/api/responses/:id/actions":                "/api/responses/1/actions",
		"/api/actions/:id/xdrop-targets":            "/api/actions/1/xdrop-targets",
		"/api/actions/:id/preconditions":            "/api/actions/1/preconditions",
		"/api/webhooks":                             "/api/webhooks",
		"/api/stats/summary":                        "/api/stats/summary",
		"/api/baseline":                             "/api/baseline",
		"/api/stats/timeseries":                     "/api/stats/timeseries?prefix=198.51.100.0/24",
		"/api/stats/overview":                       "/api/stats/overview",
		"/api/stats/total-timeseries":               "/api/stats/total-timeseries",
		"/api/attacks":                              "/api/attacks",
		"/api/attacks/active":                       "/api/attacks/active",
		"/api/attacks/mitigation-brief":             "/api/attacks/mitigation-brief?ids=1",
		"/api/attacks/:id":                          "/api/attacks/1",
		"/api/attacks/:id/action-log":               "/api/attacks/1/action-log",
		"/api/attacks/:id/sensor-logs":              "/api/attacks/1/sensor-logs",
		"/api/attacks/:id/mitigation-summary":       "/api/attacks/1/mitigation-summary",
		"/api/active-actions/bgp":                   "/api/active-actions/bgp",
		"/api/active-actions/xdrop":                 "/api/active-actions/xdrop",
		"/api/active-actions/xdrop/delivery":        "/api/active-actions/xdrop/delivery?connector_id=1&rule_id=r",
		"/api/active-actions/timeline":              "/api/active-actions/timeline?attack_id=1&external_rule_id=r",
		"/api/active-actions/bgp/dismissed-orphans": "/api/active-actions/bgp/dismissed-orphans",
		"/api/audit-log":                            "/api/audit-log",
		"/api/dynamic-detection/config":             "/api/dynamic-detection/config",
		"/api/dynamic-detection/status":             "/api/dynamic-detection/status",
		"/api/settings/webhook-connectors":          "/api/settings/webhook-connectors",
		"/api/settings/webhook-connectors/:id":      "/api/settings/webhook-connectors/1",
		"/api/settings/xdrop-connectors":            "/api/settings/xdrop-connectors",
		"/api/settings/xdrop-connectors/:id":        "/api/settings/xdrop-connectors/1",
		"/api/settings/shell-connectors":            "/api/settings/shell-connectors",
		"/api/settings/shell-connectors/:id":        "/api/settings/shell-connectors/1",
		"/api/settings/bgp-connectors":              "/api/settings/bgp-connectors",
		"/api/settings/bgp-connectors/:id":          "/api/settings/bgp-connectors/1",
		"/api/settings/bgp-connectors/:id/routes":   "/api/settings/bgp-connectors/1/routes",
		"/api/flow-listeners":                       "/api/flow-listeners?node_id=dao14-n1",
		"/api/flow-listeners/:id":                   "/api/flow-listeners/1",
		"/api/flow-sources":                         "/api/flow-sources?listener_id=1",
		"/api/flow-sources/:id":                     "/api/flow-sources/1",
		"/api/flowspec/announcements":               "/api/flowspec/announcements",
		"/api/l7/summary":                           "/api/l7/summary?window_minutes=5",
		"/api/l7/events":                            "/api/l7/events?limit=10",
		"/api/nodes/:id/tls":                        "/api/nodes/dao14-n1/tls",
		"/api/nodes/posture":                        "/api/nodes/posture",
		"/api/nodes/:id/posture":                    "/api/nodes/dao14-n1/posture",
		"/api/inline/mitigations":                   "/api/inline/mitigations",
	}
	count := 0
	for _, route := range r.Routes() {
		if route.Method != "GET" || route.Path == "/metrics" {
			continue
		}
		path, found := paths[route.Path]
		if !found {
			t.Fatalf("GET route missing from fixture: %s", route.Path)
		}
		count++
		t.Run(route.Path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			req.Header.Set("X-API-Key", "dao14d1-key")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if !json.Valid(w.Body.Bytes()) || w.Code == 400 || w.Code == 503 {
				t.Errorf("FIXTURE %s status=%d body=%s", path, w.Code, w.Body)
			}
		})
	}
	if count != 57 || count != len(paths) {
		t.Fatalf("probed=%d inventory=%d want=57", count, len(paths))
	}
	t.Logf("probed %d GET routes", count)
}
