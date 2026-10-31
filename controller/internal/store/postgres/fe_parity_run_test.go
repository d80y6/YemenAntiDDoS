package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/littlewolf9527/xsight/controller/internal/api"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

const feData = "testdata/mock-parity"
const feAPIKey = "fe-parity-test-only"

type feSeed struct {
	Users         []store.User              `json:"users"`
	Audit         []store.AuditLog          `json:"audit"`
	FlowListeners []store.FlowListener      `json:"flow_listeners"`
	FlowSources   []store.FlowSource        `json:"flow_sources"`
	Prefixes      []store.WatchPrefix       `json:"prefixes"`
	Templates     []store.ThresholdTemplate `json:"templates"`
	Rules         []store.Threshold         `json:"rules"`
	Responses     []store.Response          `json:"responses"`
	Actions       []struct {
		store.ResponseAction
		TargetNodeIDs []int `json:"target_node_ids"`
	} `json:"actions"`
	Conditions []store.ActionPrecondition `json:"conditions"`
	Config     store.DynDetectConfig      `json:"config"`
	Connectors struct {
		Webhook []store.WebhookConnector `json:"webhook"`
		Shell   []store.ShellConnector   `json:"shell"`
		BGP     []store.BGPConnector     `json:"bgp"`
		XDrop   []struct {
			store.XDropConnector
			MaskedKey string `json:"api_key"`
		} `json:"xdrop"`
	} `json:"connectors"`
	Nodes         []store.Node `json:"nodes"`
	Announcements []struct {
		store.BGPAnnouncement
		AnnouncementID int `json:"announcement_id"`
	} `json:"announcements"`
}

func feRead(t *testing.T, path string, out any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
}
func feLoadMem(t *testing.T) *feMemory {
	t.Helper()
	var seed feSeed
	feRead(t, filepath.Join(feData, "seed.json"), &seed)
	m := &feMemory{
		users: map[int]store.User{}, audit: map[int]store.AuditLog{},
		prefixes: map[int]store.WatchPrefix{}, templates: map[int]store.ThresholdTemplate{},
		rules: map[int]store.Threshold{}, responses: map[int]store.Response{}, actions: map[int]store.ResponseAction{},
		conditions: map[int]store.ActionPrecondition{}, targets: map[int][]int{}, nodes: map[string]store.Node{},
		announcements: map[int]store.BGPAnnouncement{}, webhook: map[int]store.WebhookConnector{},
		shell: map[int]store.ShellConnector{}, bgp: map[int]store.BGPConnector{}, xdrop: map[int]store.XDropConnector{},
		listeners: map[int]store.FlowListener{}, sources: map[int]store.FlowSource{},
		config: seed.Config, seq: map[string]int{"action": 99},
	}
	maxID := func(table string, id int) {
		if id > m.seq[table] {
			m.seq[table] = id
		}
	}
	for _, v := range seed.Users {
		v.Password = "parity-seed-not-a-hash"
		m.users[v.ID] = v
		maxID("user", v.ID)
	}
	for _, v := range seed.Audit {
		m.audit[v.ID] = v
	}
	for _, p := range seed.Prefixes {
		m.prefixes[p.ID] = p
		maxID("prefix", p.ID)
	}
	for _, v := range seed.Templates {
		v.RuleCount, v.PrefixCount = 0, 0
		m.templates[v.ID] = v
		maxID("template", v.ID)
	}
	for _, v := range seed.Rules {
		m.rules[v.ID] = v
		maxID("rule", v.ID)
	}
	for _, v := range seed.Responses {
		v.ActionCount, v.BoundTemplateCount = 0, 0
		m.responses[v.ID] = v
		maxID("response", v.ID)
	}
	// Decode model fields only. Enriched connector/xdrop view fields never enter response_actions.
	for _, v := range seed.Actions {
		m.actions[v.ID] = v.ResponseAction
		m.targets[v.ID] = v.TargetNodeIDs
	}
	for _, v := range seed.Conditions {
		m.conditions[v.ID] = v
		maxID("condition", v.ID)
	}
	for _, v := range seed.Connectors.Webhook {
		m.webhook[v.ID] = v
	}
	for _, v := range seed.Connectors.Shell {
		m.shell[v.ID] = v
	}
	for _, v := range seed.Connectors.BGP {
		m.bgp[v.ID] = v
	}
	for _, v := range seed.Connectors.XDrop {
		// Synthetic key has exactly the already-public mask; never read credentials.
		v.XDropConnector.APIKey = v.MaskedKey
		m.xdrop[v.ID] = v.XDropConnector
	}
	for _, v := range seed.Nodes {
		v.APIKey = feAPIKey
		m.nodes[v.ID] = v
	}
	for _, v := range seed.FlowListeners {
		m.listeners[v.ID] = v
		maxID("listener", v.ID)
	}
	for _, v := range seed.FlowSources {
		m.sources[v.ID] = v
		maxID("source", v.ID)
	}
	for _, v := range seed.Announcements {
		v.ID = v.AnnouncementID
		m.announcements[v.ID] = v.BGPAnnouncement
		maxID("announcement", v.ID)
	}
	return m
}

// Explicit table/column lists keep view fields out of SQL. All ids come from the exported seed.
func feLoadPG(t *testing.T, db *PGStore) {
	t.Helper()
	m := feLoadMem(t)
	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Pool().Exec(ctx, query, args...); err != nil {
			t.Fatalf("seed %s: %v", query, err)
		}
	}
	insert := func(table, columns string, args ...any) {
		t.Helper()
		marks := make([]string, len(args))
		for i := range args {
			marks[i] = fmt.Sprintf("$%d", i+1)
		}
		exec("INSERT INTO "+table+" ("+columns+") VALUES ("+strings.Join(marks, ",")+")", args...)
	}
	for _, v := range feAll(m.users) {
		insert("users", "id,username,password,role,enabled,created_at,updated_at",
			v.ID, v.Username, "parity-seed-not-a-hash", v.Role, v.Enabled, v.CreatedAt, v.UpdatedAt)
	}
	for _, v := range feAll(m.audit) {
		insert("config_audit_log", "id,user_id,entity_type,entity_id,action,diff,delivery_version,created_at",
			v.ID, v.UserID, v.EntityType, v.EntityID, v.Action, v.Diff, v.DeliveryVersion, v.CreatedAt)
	}
	for _, v := range feAll(m.webhook) {
		insert("webhook_connectors", "id,name,url,method,headers,timeout_ms,global,enabled,created_at,updated_at",
			v.ID, v.Name, v.URL, v.Method, v.Headers, v.TimeoutMs, v.Global, v.Enabled, v.CreatedAt, v.UpdatedAt)
	}
	for _, v := range feAll(m.shell) {
		insert("shell_connectors", "id,name,command,default_args,timeout_ms,pass_stdin,enabled,created_at,updated_at",
			v.ID, v.Name, v.Command, v.DefaultArgs, v.TimeoutMs, v.PassStdin, v.Enabled, v.CreatedAt, v.UpdatedAt)
	}
	for _, v := range feAll(m.bgp) {
		insert("bgp_connectors", "id,name,vtysh_path,bgp_asn,address_family,enabled,description,created_at,updated_at",
			v.ID, v.Name, v.VtyshPath, v.BGPASN, v.AddressFamily, v.Enabled, v.Description, v.CreatedAt, v.UpdatedAt)
	}
	for _, v := range feAll(m.xdrop) {
		insert("xdrop_connectors", "id,name,api_url,api_key,timeout_ms,enabled,created_at,updated_at",
			v.ID, v.Name, v.APIURL, v.APIKey, v.TimeoutMs, v.Enabled, v.CreatedAt, v.UpdatedAt)
	}
	for _, v := range feAll(m.responses) {
		insert("responses", "id,name,description,enabled,created_at", v.ID, v.Name, v.Description, v.Enabled, v.CreatedAt)
	}
	for _, v := range feAll(m.templates) {
		insert("threshold_templates", "id,name,description,response_id,created_at,updated_at",
			v.ID, v.Name, v.Description, v.ResponseID, v.CreatedAt, v.UpdatedAt)
	}
	for _, v := range feAll(m.prefixes) {
		insert("watch_prefixes", "id,prefix,parent_id,threshold_template_id,name,ip_group,enabled,created_at",
			v.ID, v.Prefix, v.ParentID, v.ThresholdTemplateID, v.Name, v.IPGroup, v.Enabled, v.CreatedAt)
	}
	for _, v := range feAll(m.rules) {
		insert("thresholds", thresholdCols, v.ID, v.TemplateID, v.PrefixID, v.Domain, v.Direction, v.Decoder, v.Unit,
			v.Comparison, v.Value, v.Inheritable, v.ResponseID, v.Enabled, v.CreatedAt)
	}
	for _, v := range feAll(m.actions) {
		insert("response_actions", actionCols, v.ID, v.ResponseID, v.ActionType, v.ExecutionPolicy, v.Priority,
			v.Config, v.Preconditions, v.Enabled, v.TriggerPhase, v.RunMode, v.PeriodSeconds, v.Execution,
			v.WebhookConnectorID, v.ShellConnectorID, v.XDropAction, v.XDropCustomPayload, v.ShellExtraArgs,
			v.UnblockDelayMinutes, v.BGPConnectorID, v.BGPRouteMap, v.BGPWithdrawDelayMinutes, nil, v.AutoGenerated)
	}
	for _, v := range feAll(m.actions) {
		if v.PairedWith != nil {
			exec("UPDATE response_actions SET paired_with=$1 WHERE id=$2", v.PairedWith, v.ID)
		}
		for _, id := range m.targets[v.ID] {
			insert("response_action_xdrop_targets", "action_id,connector_id", v.ID, id)
		}
	}
	for _, v := range feAll(m.conditions) {
		insert("action_preconditions", "id,action_id,attribute,operator,value,created_at",
			v.ID, v.ActionID, v.Attribute, v.Operator, v.Value, v.CreatedAt)
	}
	for _, v := range m.nodes {
		insert("nodes", "id,api_key,description,mode,enabled,created_at,updated_at",
			v.ID, v.APIKey, v.Description, v.Mode, v.Enabled, v.CreatedAt, v.UpdatedAt)
	}
	for _, v := range feAll(m.listeners) {
		insert("flow_listeners", "id,node_id,listen_address,protocol_mode,enabled,description,created_at",
			v.ID, v.NodeID, v.ListenAddress, v.ProtocolMode, v.Enabled, v.Description, v.CreatedAt)
	}
	for _, v := range feAll(m.sources) {
		insert("flow_sources", "id,listener_id,name,device_ip,sample_mode,sample_rate,description,enabled,created_at",
			v.ID, v.ListenerID, v.Name, v.DeviceIP, v.SampleMode, v.SampleRate, v.Description, v.Enabled, v.CreatedAt)
	}
	for _, v := range feAll(m.announcements) {
		insert("bgp_announcements", "id,prefix,route_map,connector_id,status,refcount",
			v.ID, v.Prefix, v.RouteMap, v.ConnectorID, v.Status, v.Refcount)
	}
	c := m.config
	exec(`UPDATE dynamic_detection_config SET enabled=$1,deviation_min=$2,deviation_max=$3,
		stable_weeks=$4,min_pps=$5,min_bps=$6,ewma_alpha=$7 WHERE id=1`,
		c.Enabled, c.DeviationMin, c.DeviationMax, c.StableWeeks, c.MinPPS, c.MinBPS, c.EWMAAlpha)
	for _, table := range []string{"watch_prefixes", "threshold_templates", "thresholds", "responses",
		"response_actions", "action_preconditions", "webhook_connectors", "shell_connectors",
		"bgp_connectors", "xdrop_connectors", "bgp_announcements", "flow_listeners", "flow_sources", "users", "config_audit_log"} {
		exec("SELECT setval(pg_get_serial_sequence('" + table + "','id'),COALESCE(MAX(id),1),COUNT(*)>0) FROM " + table)
	}
	exec("SELECT setval(pg_get_serial_sequence('response_actions','id'),99,true)")
}

type feStep struct {
	ID     string          `json:"id"`
	Site   string          `json:"site"`
	Why    string          `json:"why"`
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"`
	Reads  []string        `json:"reads"`
	Mask   []struct {
		Path string `json:"path"`
		Why  string `json:"why"`
	} `json:"mask"`
}
type feResult struct {
	Status int `json:"status"`
	Body   any `json:"body"`
}
type feRecord struct {
	ID     string   `json:"id"`
	Path   string   `json:"path"`
	Result feResult `json:"result"`
}

func feGuard(ctx context.Context, s store.Store, step feStep) error {
	if step.Path != "/api/active-actions/bgp/orphan-force-withdraw" {
		return nil
	}
	var body struct {
		ID int `json:"announcement_id"`
	}
	if err := json.Unmarshal(step.Body, &body); err != nil {
		return err
	}
	a, err := s.BGPAnnouncements().Get(ctx, body.ID)
	if err != nil {
		return fmt.Errorf("parity guard lookup: %w", err)
	}
	if a != nil && a.Status == "orphan" {
		return fmt.Errorf("parity safety guard: refusing orphan-force-withdraw announcement_id=%d current status=orphan", body.ID)
	}
	return nil
}
func feNormalize(path string, v any) any {
	var walk func(any) any
	walk = func(value any) any {
		switch x := value.(type) {
		case map[string]any:
			out := map[string]any{}
			for k, v := range x {
				if strings.HasSuffix(k, "_at") && v != nil {
					out[k] = "<ts>"
				} else {
					out[k] = walk(v)
				}
			}
			return out
		case []any:
			out := make([]any, len(x))
			for i, v := range x {
				out[i] = walk(v)
			}
			return out
		}
		return value
	}
	out := walk(v)
	var rows []any
	var keys []string
	switch {
	case path == "/api/thresholds":
		rows, _ = out.([]any)
		keys = []string{"prefix_id", "template_id", "decoder"}
	case regexp.MustCompile(`^/api/threshold-templates/\d+$`).MatchString(path):
		if obj, ok := out.(map[string]any); ok {
			rows, _ = obj["rules"].([]any)
			keys = []string{"decoder", "unit"}
		}
	case regexp.MustCompile(`^/api/responses/\d+$`).MatchString(path):
		if obj, ok := out.(map[string]any); ok {
			rows, _ = obj["actions"].([]any)
			keys = []string{"trigger_phase", "priority"}
		}
	}
	same := func(a, b any) bool {
		x, xok := a.(map[string]any)
		y, yok := b.(map[string]any)
		if !xok || !yok {
			return false
		}
		for _, k := range keys {
			if !reflect.DeepEqual(x[k], y[k]) {
				return false
			}
		}
		return true
	}
	for start := 0; start < len(rows); {
		end := start + 1
		for end < len(rows) && same(rows[start], rows[end]) {
			end++
		}
		sort.SliceStable(rows[start:end], func(i, j int) bool {
			return rows[start+i].(map[string]any)["id"].(float64) < rows[start+j].(map[string]any)["id"].(float64)
		})
		start = end
	}
	return out
}
func feDifference(a, b any, path string) string {
	if reflect.DeepEqual(a, b) {
		return ""
	}
	if x, ok := a.(map[string]any); ok {
		if y, ok := b.(map[string]any); ok {
			keys := map[string]bool{}
			for k := range x {
				keys[k] = true
			}
			for k := range y {
				keys[k] = true
			}
			var ordered []string
			for k := range keys {
				ordered = append(ordered, k)
			}
			sort.Strings(ordered)
			for _, k := range ordered {
				xv, xok := x[k]
				yv, yok := y[k]
				if xok != yok {
					return fmt.Sprintf("%s.%s: key present %v != %v", path, k, xok, yok)
				}
				if d := feDifference(xv, yv, path+"."+k); d != "" {
					return d
				}
			}
		}
	}
	if x, ok := a.([]any); ok {
		if y, ok := b.([]any); ok {
			if len(x) != len(y) {
				return fmt.Sprintf("%s.length: %d != %d", path, len(x), len(y))
			}
			for i := range x {
				if d := feDifference(x[i], y[i], fmt.Sprintf("%s[%d]", path, i)); d != "" {
					return d
				}
			}
		}
	}
	return fmt.Sprintf("%s: %v != %v", path, a, b)
}
func feCompare(path string, a, b feResult) string {
	if a.Status != b.Status {
		return fmt.Sprintf("$.status: %d != %d", a.Status, b.Status)
	}
	return feDifference(feNormalize(path, a.Body), feNormalize(path, b.Body), "$.body")
}

const feExpected500 = `[["qh-source-int32-overflow","POST","/api/flow-sources","database error"],
["qh-source-int32-update-overflow","PUT","/api/flow-sources/9","database error"],
["qi-user-pw-73","POST","/api/users","hash failed"],
["qi-user-pw-multibyte","POST","/api/users","hash failed"],
["qi-user-pw-update-73","PUT","/api/users/9","hash failed"]]`

func feApparatus(id, method, path string, status int, raw []byte) (any, error) {
	var value any
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty response")
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("JSON: %w", err)
	}
	var allowed [][4]string
	if err := json.Unmarshal([]byte(feExpected500), &allowed); err != nil {
		return nil, err
	}
	for _, entry := range allowed {
		if id == entry[0] && method == entry[1] && path == entry[2] {
			if status != 500 || !reflect.DeepEqual(value, map[string]any{"error": entry[3]}) {
				return nil, fmt.Errorf("expected exact 500 %s, got %d %s", entry[3], status, raw)
			}
			return value, nil
		}
	}
	if status >= 500 {
		return nil, fmt.Errorf("unexpected status %d: %s", status, raw)
	}
	return value, nil
}

func TestFEParityApparatus(t *testing.T) {
	for _, sample := range []struct {
		id, method, path, body string
		status                 int
		bad                    bool
	}{
		{"qi-user-pw-73", "POST", "/api/users", `{"error":"database error"}`, 500, true},
		{"qh-source-int32-overflow", "POST", "/api/flow-sources", `{"error":"hash failed"}`, 500, true},
		{"qi-user-pw-73", "GET", "/api/users", `{"error":"hash failed"}`, 500, true},
		{"unlisted-step", "POST", "/api/users", `{"error":"hash failed"}`, 500, true},
		{"qi-user-pw-update-73", "PUT", "/api/users/10", `{"error":"hash failed"}`, 500, true},
		{"qi-user-pw-73", "POST", "/api/users", `{"error":"hash failed"}`, 500, false},
		{"qi-user-pw-multibyte", "POST", "/api/users", `{"error":"hash failed"}`, 500, false},
		{"qi-user-pw-update-73", "PUT", "/api/users/9", `{"error":"hash failed"}`, 500, false},
		{"unlisted-step", "POST", "/api/flow-sources", `{"error":"database error"}`, 500, true},
		{"qh-source-int32-overflow", "POST", "/api/flow-sources", `{"error":"x"}`, 500, true},
		{"qh-source-int32-overflow", "GET", "/api/flow-sources", `{"error":"database error"}`, 500, true},
		{"qh-source-int32-overflow", "POST", "/api/flow-sources/9", `{"error":"database error"}`, 500, true},
		{"qh-source-int32-overflow", "POST", "/api/flow-sources", `{"error":"database error"}`, 201, true},
		{"qh-source-int32-overflow", "POST", "/api/flow-sources", `{"error":"database error","extra":1}`, 500, true},
		{"ordinary", "GET", "/api/flow-sources", ``, 200, true},
		{"ordinary", "GET", "/api/flow-sources", `not JSON`, 200, true},
		{"qh-source-int32-overflow", "POST", "/api/flow-sources", `{"error":"database error"}`, 500, false},
		{"qh-source-int32-update-overflow", "PUT", "/api/flow-sources/9", `{"error":"database error"}`, 500, false},
		{"ordinary", "GET", "/api/flow-sources", `[]`, 200, false},
	} {
		_, err := feApparatus(sample.id, sample.method, sample.path, sample.status, []byte(sample.body))
		if (err != nil) != sample.bad {
			t.Errorf("W37 apparatus %s %s %s: error=%v, want apparatus error=%t",
				sample.id, sample.method, sample.path, err, sample.bad)
		}
	}
}

func feRun(t *testing.T, s store.Store, update bool) {
	t.Helper()
	var manifest struct {
		Steps []feStep `json:"steps"`
	}
	feRead(t, filepath.Join(feData, "requests.json"), &manifest)
	goldenPath := os.Getenv("XSIGHT_PARITY_GOLDEN")
	if goldenPath == "" {
		goldenPath = filepath.Join(feData, "golden.json")
	} else if update || !filepath.IsAbs(goldenPath) {
		t.Fatal("XSIGHT_PARITY_GOLDEN must be an absolute read-only override; unset it before updating")
	}
	var golden []feRecord
	if !update {
		feRead(t, goldenPath, &golden)
	}
	router := api.NewRouter(api.Dependencies{Store: s, APIKey: feAPIKey})
	var actual []feRecord
	writes := 0
	reads := 0
	writeReads := 0
	for _, step := range manifest.Steps {
		if len(step.Mask) != 0 {
			t.Fatalf("unsupported mask in %s: pinned mask list is empty", step.ID)
		}
		if step.Method != "GET" {
			writes++
		}
		if err := feGuard(context.Background(), s, step); err != nil {
			t.Fatalf("%s: %v", step.ID, err)
		}
		paths := append([]string{step.Path}, step.Reads...)
		for i, path := range paths {
			method, body := step.Method, step.Body
			if i > 0 {
				method, body = "GET", nil
				reads++
				if step.Method != "GET" {
					writeReads++
				}
			}
			req := httptest.NewRequest(method, path, bytes.NewReader(body))
			req.Header.Set("X-API-Key", feAPIKey)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			value, err := feApparatus(step.ID, method, path, rec.Code, rec.Body.Bytes())
			if err != nil {
				t.Fatalf("apparatus %s %s %s: %v", step.ID, method, path, err)
			}
			result := feResult{rec.Code, feNormalize(path, value)}
			index := len(actual)
			actual = append(actual, feRecord{step.ID, path, result})
			if !update {
				if index >= len(golden) {
					t.Fatalf("extra record %s %s", step.ID, path)
				}
				want := golden[index]
				if want.ID != step.ID || want.Path != path {
					t.Fatalf("record %d identity: %s %s != %s %s", index, step.ID, path, want.ID, want.Path)
				}
				if diff := feCompare(path, result, want.Result); diff != "" {
					t.Fatalf("%s · %s %s · read=%t · %s", step.ID, method, path, i > 0, diff)
				}
			}
		}
	}
	if len(manifest.Steps) < 60 || writes < 45 || reads < 100 || writeReads < 100 {
		t.Fatalf("empty coverage: steps=%d writes=%d reads=%d", len(manifest.Steps), writes, reads)
	}
	if update {
		b, err := json.MarshalIndent(actual, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(goldenPath, append(b, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	} else if len(actual) != len(golden) {
		t.Fatalf("record count %d != %d", len(actual), len(golden))
	}
	t.Logf("G-parity steps=%d writes=%d reads=%d write_reads=%d records=%d", len(manifest.Steps), writes, reads, writeReads, len(actual))
}
func feCheckCIDR(t *testing.T, parse func(string) (string, error)) {
	t.Helper()
	var corpus struct {
		Entries []struct {
			Input string `json:"input"`
			Text  string `json:"text"`
			Error string `json:"error"`
		} `json:"entries"`
	}
	feRead(t, filepath.Join(feData, "cidr-corpus.json"), &corpus)
	if len(corpus.Entries) != 75 {
		t.Fatalf("G-cidr corpus count=%d want 75", len(corpus.Entries))
	}
	valid, rejected := 0, 0
	for _, entry := range corpus.Entries {
		got, err := parse(entry.Input)
		var pgerr *pgconn.PgError
		if entry.Error != "" {
			rejected++
			if entry.Error != "22P02" || !errors.As(err, &pgerr) || pgerr.Code != entry.Error {
				t.Errorf("G-cidr %q: text=%q error=%v; want %s", entry.Input, got, err, entry.Error)
			}
		} else {
			valid++
			if err != nil || got != entry.Text {
				t.Errorf("G-cidr %q: text=%q error=%v; want %q", entry.Input, got, err, entry.Text)
			}
		}
	}
	if valid != 53 || rejected != 22 {
		t.Fatalf("G-cidr text=%d error=%d want 53/22", valid, rejected)
	}
	t.Logf("G-cidr entries=75 text=%d error=%d", valid, rejected)
}
func TestFEParityMem(t *testing.T) {
	if !t.Run("G-cidr", func(t *testing.T) { feCheckCIDR(t, feCIDR) }) {
		return
	}
	feRun(t, feLoadMem(t), os.Getenv("XSIGHT_PARITY_UPDATE") == "1")
}
func TestFEParityPG(t *testing.T) {
	b := newPostgresContractBackend(t).(*postgresContractBackend)
	if !t.Run("G-cidr-live", func(t *testing.T) {
		feCheckCIDR(t, func(input string) (string, error) {
			var text string
			err := b.db.Pool().QueryRow(context.Background(), "SELECT $1::cidr::text", input).Scan(&text)
			return text, err
		})
	}) {
		return
	}
	if !t.Run("G-inet-live", func(t *testing.T) {
		for _, entry := range feINETCorpus(t) {
			if !entry.GoValid {
				continue
			}
			var text string
			err := b.db.Pool().QueryRow(context.Background(), "SELECT $1::inet::text", entry.Input).Scan(&text)
			if err != nil || text != entry.PGText {
				t.Errorf("G-inet %q: %q %v; want %q", entry.Input, text, err, entry.PGText)
			}
		}
	}) {
		return
	}
	feLoadPG(t, b.db)
	feRun(t, b.db, false)
}
func TestFEParityGuard(t *testing.T) {
	m := feLoadMem(t)
	step := feStep{Path: "/api/active-actions/bgp/orphan-force-withdraw", Body: json.RawMessage(`{"announcement_id":20}`)}
	if err := feGuard(context.Background(), m, step); err != nil {
		t.Fatal(err)
	}
	if err := m.BGPAnnouncements().Undismiss(context.Background(), 20); err != nil {
		t.Fatal(err)
	}
	want := "parity safety guard: refusing orphan-force-withdraw announcement_id=20 current status=orphan"
	if err := feGuard(context.Background(), m, step); err == nil || err.Error() != want {
		t.Fatalf("guard: %v; want %s", err, want)
	}
}
func TestFEParityCompare(t *testing.T) {
	decode := func(raw string) any {
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, tc := range []struct {
		name, path, a, b string
		sa, sb           int
		equal            bool
	}{
		{"status", "/api/responses", `{"error":"same"}`, `{"error":"same"}`, 409, 400, false},
		{"error", "/api/responses", `{"error":"one"}`, `{"error":"two"}`, 400, 400, false},
		{"timestamps", "/api/responses", `{"created_at":"a"}`, `{"created_at":"b"}`, 200, 200, true},
		{"null timestamp", "/api/responses", `{"created_at":null}`, `{"created_at":"b"}`, 200, 200, false},
		{"same segment", "/api/thresholds", `[{"id":2,"decoder":"ip"},{"id":1,"decoder":"ip"}]`, `[{"id":1,"decoder":"ip"},{"id":2,"decoder":"ip"}]`, 200, 200, true},
		{"cross segment", "/api/thresholds", `[{"id":2,"decoder":"tcp"},{"id":1,"decoder":"ip"}]`, `[{"id":1,"decoder":"ip"},{"id":2,"decoder":"tcp"}]`, 200, 200, false},
		{"template segment", "/api/threshold-templates/7", `{"rules":[{"id":2,"decoder":"ip","unit":"pps"},{"id":1,"decoder":"ip","unit":"pps"}]}`, `{"rules":[{"id":1,"decoder":"ip","unit":"pps"},{"id":2,"decoder":"ip","unit":"pps"}]}`, 200, 200, true},
		{"template cross segment", "/api/threshold-templates/7", `{"rules":[{"id":2,"decoder":"ip","unit":"bps"},{"id":1,"decoder":"ip","unit":"pps"}]}`, `{"rules":[{"id":1,"decoder":"ip","unit":"pps"},{"id":2,"decoder":"ip","unit":"bps"}]}`, 200, 200, false},
		{"action segment", "/api/responses/3", `{"actions":[{"id":2,"priority":5},{"id":1,"priority":5}]}`, `{"actions":[{"id":1,"priority":5},{"id":2,"priority":5}]}`, 200, 200, true},
		{"action cross segment", "/api/responses/3", `{"actions":[{"id":2,"priority":2},{"id":1,"priority":5}]}`, `{"actions":[{"id":1,"priority":5},{"id":2,"priority":2}]}`, 200, 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := feCompare(tc.path, feResult{tc.sa, decode(tc.a)}, feResult{tc.sb, decode(tc.b)})
			if (d == "") != tc.equal {
				t.Fatalf("equality=%v want %v: %s", d == "", tc.equal, d)
			}
		})
	}
}
