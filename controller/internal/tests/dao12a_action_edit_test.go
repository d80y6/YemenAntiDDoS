package tests

import (
	"bufio"
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
)

// Copy at repository boundaries, including recorded arguments, so the mock's
// pointer and RawMessage aliases cannot hide a damaged rollback snapshot.
func dao12aCopy[T any](v T) T {
	var b bytes.Buffer
	if err := gob.NewEncoder(&b).Encode(v); err != nil {
		panic(err)
	}
	var out T
	if err := gob.NewDecoder(&b).Decode(&out); err != nil {
		panic(err)
	}
	return out
}

type dao12aKey struct {
	method string
	id, n  int
}
type dao12aWrite struct {
	method string
	id     int
	row    *store.ResponseAction
	ids    []int
}
type dao12aStore struct {
	*MockStore
	mu     sync.Mutex
	calls  map[dao12aKey]int
	faults map[dao12aKey]string
	writes []dao12aWrite
	global string
}

func dao12aNew() *dao12aStore {
	return &dao12aStore{MockStore: NewMockStore(), calls: map[dao12aKey]int{}, faults: map[dao12aKey]string{}}
}
func (s *dao12aStore) call(method string, id int, row *store.ResponseAction, ids []int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := dao12aKey{method: method, id: id}
	s.calls[key]++
	if method == "UpdateAction" || method == "CreateAction" || method == "Set" {
		var copy *store.ResponseAction
		if row != nil {
			copy = dao12aCopy(row)
		}
		s.writes = append(s.writes, dao12aWrite{method, id, copy, slices.Clone(ids)})
	}
	key.n = s.calls[key]
	return s.faults[key]
}
func (s *dao12aStore) Responses() store.ResponseRepo {
	return dao12aRows{s.MockStore.Responses(), s}
}
func (s *dao12aStore) XDropTargets() store.XDropTargetRepo {
	return dao12aTargets{s.MockStore.XDropTargets(), s}
}
func (s *dao12aStore) Prefixes() store.PrefixRepo {
	return dao12aPrefixes{s.MockStore.Prefixes(), s}
}
func (s *dao12aStore) WebhookConnectors() store.WebhookConnectorRepo {
	return dao12aWebhooks{s.MockStore.WebhookConnectors()}
}
func (s *dao12aStore) Thresholds() store.ThresholdRepo {
	return dao12aThresholds{s.MockStore.Thresholds(), s}
}

type dao12aThresholds struct {
	store.ThresholdRepo
	s *dao12aStore
}

func (r dao12aThresholds) List(c context.Context) ([]store.Threshold, error) {
	if r.s.global == "referenced" {
		return []store.Threshold{{ID: 9, PrefixID: intPtr(8), ResponseID: intPtr(1)}}, nil
	}
	return r.ThresholdRepo.List(c)
}

type dao12aWebhooks struct{ store.WebhookConnectorRepo }

func (dao12aWebhooks) Get(_ context.Context, id int) (*store.WebhookConnector, error) {
	if id != 7 {
		return nil, errors.New("connector not found")
	}
	return &store.WebhookConnector{ID: 7, Name: "dao12a", URL: "http://dao12a.invalid/hook", Method: "POST", Enabled: true}, nil
}

type dao12aRows struct {
	store.ResponseRepo
	s *dao12aStore
}

func (r dao12aRows) GetAction(c context.Context, id int) (*store.ResponseAction, error) {
	if fault := r.s.call("GetAction", id, nil, nil); fault != "" {
		if fault == "nil" {
			return nil, nil
		}
		return nil, errors.New(fault)
	}
	a, err := r.ResponseRepo.GetAction(c, id)
	if a != nil {
		a = dao12aCopy(a)
	}
	return a, err
}
func (r dao12aRows) ListActions(c context.Context, id int) ([]store.ResponseAction, error) {
	rows, err := r.ResponseRepo.ListActions(c, id)
	return dao12aCopy(rows), err
}
func (r dao12aRows) CreateAction(c context.Context, a *store.ResponseAction) (int, error) {
	r.s.call("CreateAction", a.ID, a, nil)
	return r.ResponseRepo.CreateAction(c, dao12aCopy(a))
}
func (r dao12aRows) UpdateAction(c context.Context, a *store.ResponseAction) error {
	if fault := r.s.call("UpdateAction", a.ID, a, nil); fault != "" {
		return errors.New(fault)
	}
	return r.ResponseRepo.UpdateAction(c, dao12aCopy(a))
}

type dao12aTargets struct {
	store.XDropTargetRepo
	s *dao12aStore
}

func (r dao12aTargets) List(c context.Context, id int) ([]store.XDropConnector, error) {
	if fault := r.s.call("List", id, nil, nil); fault != "" {
		return nil, errors.New(fault)
	}
	rows, err := r.XDropTargetRepo.List(c, id)
	return dao12aCopy(rows), err
}
func (r dao12aTargets) Set(c context.Context, id int, ids []int) error {
	if fault := r.s.call("Set", id, nil, ids); fault != "" {
		return errors.New(fault)
	}
	return r.XDropTargetRepo.Set(c, id, slices.Clone(ids))
}

type dao12aPrefixes struct {
	store.PrefixRepo
	s *dao12aStore
}

func (r dao12aPrefixes) List(c context.Context) ([]store.WatchPrefix, error) {
	if r.s.global == "error" {
		return nil, errors.New("global lookup failed")
	}
	if r.s.global == "referenced" {
		return []store.WatchPrefix{{ID: 8, Prefix: "0.0.0.0/0"}}, nil
	}
	return r.PrefixRepo.List(c)
}
func dao12aCheck(t *testing.T, name string, got, want any) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got=%+v; want=%+v", name, got, want)
		}
	})
}
func dao12aState(s *dao12aStore, id int) *store.ResponseAction {
	a, _ := s.MockStore.Responses().GetAction(context.Background(), id)
	return dao12aCopy(a)
}
func dao12aIDs(s *dao12aStore, id int) []int {
	rows, _ := s.MockStore.XDropTargets().List(context.Background(), id)
	ids := []int{}
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	return ids
}
func dao12aWrites(s *dao12aStore) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, w := range s.writes {
		out = append(out, fmt.Sprintf("%s:%d", w.method, w.id))
	}
	return strings.Join(out, " ")
}
func dao12aBody(kind string) map[string]any {
	b := map[string]any{"action_type": kind, "trigger_phase": "on_detected", "run_mode": "once", "execution": "automatic", "enabled": true, "priority": 1}
	if kind == "xdrop" {
		b["xdrop_action"], b["xdrop_custom_payload"] = "filter_l4", json.RawMessage(`{"dst_ip":"192.0.2.1"}`)
	} else {
		b["connector_id"] = 7
	}
	if kind == "bgp" {
		b["bgp_route_map"] = "RTBH"
	}
	return b
}
func dao12aFixture(t *testing.T, kind string, paired bool) *dao12aStore {
	t.Helper()
	s := dao12aNew()
	s.responses.responses = []store.Response{{ID: 1, Name: "dao12a", Enabled: true}}
	a := store.ResponseAction{ID: 10, ResponseID: 1, ActionType: kind, ExecutionPolicy: "once_on_enter", Priority: 1, Config: []byte(`{}`), Enabled: true, TriggerPhase: "on_detected", RunMode: "once", Execution: "automatic"}
	switch kind {
	case "xdrop":
		a.XDropAction, a.XDropCustomPayload, a.UnblockDelayMinutes = "filter_l4", []byte(`{"dst_ip":"192.0.2.1"}`), 3
	case "bgp":
		a.BGPConnectorID, a.BGPRouteMap, a.BGPWithdrawDelayMinutes = intPtr(7), "RTBH", 3
	case "webhook":
		a.WebhookConnectorID = intPtr(7)
	case "shell":
		a.ShellConnectorID = intPtr(7)
	}
	s.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Enabled: true}}
	s.xdropConnectors.connectors = []store.XDropConnector{{ID: 1, Name: "A", Enabled: true}, {ID: 2, Name: "B", Enabled: true}, {ID: 3, Name: "C", Enabled: true}, {ID: 4, Name: "D", Enabled: true}}
	if paired {
		a.PairedWith = intPtr(20)
		child := dao12aCopy(a)
		child.ID, child.PairedWith, child.AutoGenerated = 20, nil, true
		child.TriggerPhase, child.ExecutionPolicy = "on_expired", "once_on_exit"
		if kind == "xdrop" {
			child.XDropAction, child.XDropCustomPayload = "unblock", nil
		}
		s.responses.actions = append(s.responses.actions, child)
	}
	s.responses.actions = append(s.responses.actions, dao12aCopy(a))
	s.responses.nextID = 30
	if kind == "xdrop" {
		for _, id := range []int{10, 20} {
			if err := s.MockStore.XDropTargets().Set(context.Background(), id, []int{1, 2}); err != nil {
				t.Fatal(err)
			}
		}
	}
	return s
}

func TestDao12a_G1(t *testing.T) {
	var status, priority, positive int
	var kept string
	var blocked bool
	legacy := []byte(`{"severity":"critical"}`)
	synctest.Test(t, func(t *testing.T) {
		s := dao12aFixture(t, "webhook", false)
		s.responses.actions[0].Preconditions = slices.Clone(legacy)
		w := putActionRaw(t, setupTransactionRouter(s), 10, map[string]any{"priority": 9})
		a := dao12aState(s, 10)
		status, priority, kept = w.Code, a.Priority, string(a.Preconditions)
		d := dao4HTTP(t)
		e := action.NewEngine(s, "auto")
		ev := tracker.AttackEvent{Type: "confirmed", DBID: 100, Attack: &store.Attack{ID: 100, ResponseID: intPtr(1), DstIP: "192.0.2.10", Severity: "low", DecoderFamily: "udp", StartedAt: time.Now()}}
		e.HandleEvent(ev)
		synctest.Wait()
		rows := s.actionExecLog.snapshotLogs()
		blocked = d.count() == 0 && len(rows) == 1 && rows[0].SkipReason == "precondition_not_matched"
		before := d.count()
		ev.DBID, ev.Attack.ID, ev.Attack.Severity = 101, 101, "critical"
		e.HandleEvent(ev)
		synctest.Wait()
		positive = d.count() - before
	})
	dao12aCheck(t, "Status", status, 200)
	dao12aCheck(t, "Priority", priority, 9)
	dao12aCheck(t, "Kept", kept, string(legacy))
	dao12aCheck(t, "Eval", blocked, true)
	dao12aCheck(t, "EvalPos", positive, 1)
}

func TestDao12a_G2(t *testing.T) {
	for _, kind := range []string{"xdrop", "bgp"} {
		for _, cell := range []string{"a", "b", "c", "d", "e_error", "e_nil", "f", "g", "h", "i", "j", "k", "l", "m", "n"} {
			if kind == "bgp" && !slices.Contains([]string{"a", "c", "e_error", "e_nil", "g", "i"}, cell) {
				continue
			}
			t.Run(kind+"/G2"+cell, func(t *testing.T) {
				s := dao12aFixture(t, kind, true)
				parent, child := dao12aState(s, 10), dao12aState(s, 20)
				pt, ct := dao12aIDs(s, 10), dao12aIDs(s, 20)
				body := map[string]any{"enabled": false, "priority": 9}
				newIDs := []int{3}
				if cell == "n" {
					newIDs = []int{3, 4}
				}
				if kind == "xdrop" {
					body["target_node_ids"], body["unblock_delay_minutes"] = newIDs, 12
				} else {
					body["bgp_withdraw_delay_minutes"], body["bgp_route_map"] = 12, "RTBH_NEW"
				}
				if cell == "k" {
					body["xdrop_custom_payload"] = json.RawMessage(`{"dst_ip":"192.0.2.2"}`)
				}
				fault := func(method string, id, n int, msg string) { s.faults[dao12aKey{method, id, n}] = msg }
				switch cell {
				case "a":
					fault("UpdateAction", 10, 1, "parent write")
				case "b", "k", "l":
					fault("Set", 10, 1, "parent targets write")
				case "c", "i", "m", "n":
					fault("UpdateAction", 20, 1, "child write")
				case "e_error", "e_nil":
					msg := "child read"
					if cell == "e_nil" {
						msg = "nil"
					}
					fault("GetAction", 20, 1, msg)
				case "d", "f", "h", "j":
					fault("Set", 20, 1, "child targets write")
				}
				var incomplete []string
				if cell == "f" || cell == "j" {
					fault("UpdateAction", 20, 2, "child restore")
					incomplete = append(incomplete, "child row")
				}
				if cell == "h" || cell == "j" {
					fault("Set", 10, 2, "targets restore")
					incomplete = append(incomplete, "parent targets")
				}
				if cell == "i" || cell == "l" {
					fault("UpdateAction", 10, 2, "parent restore")
					incomplete = append(incomplete, "parent row")
				}
				if cell == "m" {
					fault("List", 10, 1, "targets read")
					incomplete = append(incomplete, "parent targets: previous value unknown")
				}
				var capture bytes.Buffer
				writer := log.Writer()
				log.SetOutput(&capture)
				w := putActionRaw(t, setupTransactionRouter(s), 10, body)
				log.SetOutput(writer)
				changedParent, changedChild := dao12aCopy(parent), dao12aCopy(child)
				for _, a := range []*store.ResponseAction{changedParent, changedChild} {
					a.Enabled, a.Priority = false, 9
					if kind == "xdrop" {
						a.UnblockDelayMinutes = 12
					} else {
						a.BGPWithdrawDelayMinutes, a.BGPRouteMap = 12, "RTBH_NEW"
					}
				}
				if cell == "k" {
					changedParent.XDropCustomPayload = []byte(`{"dst_ip":"192.0.2.2"}`)
				}
				status := 500
				if cell == "g" {
					status, parent, child = 200, changedParent, changedChild
					if kind == "xdrop" {
						pt, ct = newIDs, slices.Clone(newIDs)
					}
				}
				if cell == "f" || cell == "j" {
					child = changedChild
				}
				if cell == "h" || cell == "j" || cell == "m" {
					pt = newIDs
				}
				if cell == "i" || cell == "l" {
					parent = changedParent
				}
				seq := "UpdateAction:10"
				if cell != "a" {
					seq += " Set:10"
					switch cell {
					case "b", "k", "l":
					case "e_error", "e_nil":
						if kind == "xdrop" {
							seq += " Set:10"
						}
					default:
						seq += " UpdateAction:20"
						if slices.Contains([]string{"d", "f", "g", "h", "j"}, cell) && kind == "xdrop" {
							seq += " Set:20"
							if cell != "g" {
								seq += " UpdateAction:20"
							}
						}
						if cell != "g" && cell != "m" && kind == "xdrop" {
							seq += " Set:10"
						}
					}
					if cell != "g" {
						seq += " UpdateAction:10"
					}
				}
				msg := "failed to sync paired action: database error"
				switch cell {
				case "a":
					msg = "database error"
				case "b", "k", "l":
					msg = "set xdrop targets: database error"
				}
				if len(incomplete) > 0 {
					msg += "; rollback incomplete: " + strings.Join(incomplete, "; ")
				}
				var response struct {
					Error string `json:"error"`
				}
				_ = json.Unmarshal(w.Body.Bytes(), &response)
				if cell == "g" {
					msg = ""
				}
				dao12aCheck(t, "Status", w.Code, status)
				dao12aCheck(t, "Parent", dao12aState(s, 10), parent)
				dao12aCheck(t, "Child", dao12aState(s, 20), child)
				dao12aCheck(t, "ParentTargets", dao12aIDs(s, 10), pt)
				dao12aCheck(t, "ChildTargets", dao12aIDs(s, 20), ct)
				dao12aCheck(t, "Msg", response.Error, msg)
				dao12aCheck(t, "Writes", dao12aWrites(s), seq)
				dao12aCheck(t, "Logs", strings.Count(capture.String(), "action: rollback "), len(incomplete))
			})
		}
	}
}

func TestDao12a_G3(t *testing.T) {
	run := func(t *testing.T, name string) int {
		s := dao12aFixture(t, "xdrop", false)
		s.faults[dao12aKey{"List", 10, 1}] = "targets read"
		body := map[string]any{"priority": 9}
		want, status := []int{1}, 200
		switch name {
		case "Missing":
			want, status = []int{1, 2}, 500
		case "Null":
			body["target_node_ids"], want = nil, []int{}
		case "Empty":
			body["target_node_ids"], want = []int{}, []int{}
		case "Upper":
			body["TARGET_NODE_IDS"] = []int{1}
		default:
			body["target_node_ids"] = []int{1}
		}
		w := putActionRaw(t, setupTransactionRouter(s), 10, body)
		dao12aCheck(t, "Status", w.Code, status)
		dao12aCheck(t, "Targets", dao12aIDs(s, 10), want)
		if name == "Missing" {
			dao12aCheck(t, "NoWrite", dao12aWrites(s), "")
		}
		return w.Code
	}
	for _, name := range []string{"Missing", "Array", "Null", "Empty", "Upper"} {
		t.Run(name, func(t *testing.T) { run(t, name) })
	}
	t.Run("PresenceParity", func(t *testing.T) {
		codes := []int{}
		for _, value := range []any{[]int{1}, nil} {
			s := dao12aFixture(t, "xdrop", false)
			s.faults[dao12aKey{"List", 10, 1}] = "targets read"
			codes = append(codes, putActionRaw(t, setupTransactionRouter(s), 10, map[string]any{"target_node_ids": value}).Code)
		}
		if codes[0] != codes[1] {
			t.Errorf("G3.PresenceParity: array=%d; null=%d", codes[0], codes[1])
		}
	})
	t.Run("CaseParity", func(t *testing.T) {
		codes := []int{}
		for _, key := range []string{"target_node_ids", "TARGET_NODE_IDS"} {
			s := dao12aFixture(t, "xdrop", false)
			s.faults[dao12aKey{"List", 10, 1}] = "targets read"
			codes = append(codes, putActionRaw(t, setupTransactionRouter(s), 10, map[string]any{key: []int{1}}).Code)
		}
		t.Logf("G3.CaseParity: lower=%d; upper=%d", codes[0], codes[1])
		if codes[0] != codes[1] {
			t.Errorf("G3.CaseParity: lower=%d; upper=%d", codes[0], codes[1])
		}
	})
	t.Run("UnknownNumber", func(t *testing.T) {
		s := dao12aFixture(t, "webhook", false)
		w := dao12aRawRequest(t, s, `{"priority":9,"unused":1e1000}`, 0)
		dao12aCheck(t, "Status", w.Code, 200)
		dao12aCheck(t, "Priority", dao12aState(s, 10).Priority, 9)
	})
}

func TestDao12a_G2o(t *testing.T) {
	s := dao12aFixture(t, "bgp", true)
	s.bgpConnectors.connectors = append(s.bgpConnectors.connectors, store.BGPConnector{ID: 8, Enabled: true})
	s.faults[dao12aKey{"UpdateAction", 20, 1}] = "child write"
	w := putActionRaw(t, setupTransactionRouter(s), 10, map[string]any{"connector_id": 8, "priority": 9})
	connector := 0
	if id := dao12aState(s, 10).BGPConnectorID; id != nil {
		connector = *id
	}
	dao12aCheck(t, "Status", w.Code, 500)
	dao12aCheck(t, "Parent", connector, 7)
	dao12aCheck(t, "Writes", dao12aWrites(s), "UpdateAction:10 Set:10 UpdateAction:20 UpdateAction:10")
}

// A temporary Go overlay gives this gate package-local access without exporting
// cloneAction or adding a file to the API source tree.
func TestDao12a_G2p(t *testing.T) {
	t.Run("CloneIndependent", func(t *testing.T) {
		source := `package api
import (
	"testing"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)
func TestDao12aCloneOverlay(t *testing.T) {
	w, s, b, p := 1, 2, 3, 4
	a := store.ResponseAction{WebhookConnectorID: &w, ShellConnectorID: &s, BGPConnectorID: &b, PairedWith: &p,
		Config: []byte("{\"a\":1}"), Preconditions: []byte("{\"a\":2}"), XDropCustomPayload: []byte("{\"a\":3}")}
	copy := cloneAction(&a)
	for _, ptr := range []*int{copy.WebhookConnectorID, copy.ShellConnectorID, copy.BGPConnectorID, copy.PairedWith} {
		*ptr += 10
	}
	for _, data := range [][]byte{copy.Config, copy.Preconditions, copy.XDropCustomPayload} {
		data[0] = '['
	}
	for i, ptr := range []*int{a.WebhookConnectorID, a.ShellConnectorID, a.BGPConnectorID, a.PairedWith} {
		if *ptr != i+1 { t.Errorf("pointer %d original=%d; want=%d", i, *ptr, i+1) }
	}
	for i, data := range [][]byte{a.Config, a.Preconditions, a.XDropCustomPayload} {
		want := []string{"{\"a\":1}", "{\"a\":2}", "{\"a\":3}"}[i]
		if string(data) != want { t.Errorf("slice %d original=%q; want=%q", i, data, want) }
	}
}`
		unit, err := format.Source([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		virtual, err := filepath.Abs("../api/dao12a_clone_overlay_test.go")
		if err != nil {
			t.Fatal(err)
		}
		physical := filepath.Join(dir, "clone_test.go")
		overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{virtual: physical}})
		for name, data := range map[string][]byte{"clone_test.go": unit, "overlay.json": overlay} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("go", "test", "-overlay", filepath.Join(dir, "overlay.json"), "../api", "-run", "^TestDao12aCloneOverlay$", "-count=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("G2p.CloneIndependent: %v\n%s", err, output)
		}
	})
}

func dao12aRawRequest(t *testing.T, s *dao12aStore, body string, excess int) *httptest.ResponseRecorder {
	t.Helper()
	req := dao12aWire(t, body, excess)
	defer req.Body.Close()
	return dao12aServe(s, req)
}
func dao12aWire(t *testing.T, body string, excess int) *http.Request {
	t.Helper()
	wire := fmt.Sprintf("PUT /api/actions/10 HTTP/1.1\r\nHost: dao12a.invalid\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body)+excess, body)
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(wire)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	return req
}
func dao12aServe(s *dao12aStore, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	setupTransactionRouter(s).ServeHTTP(w, req)
	return w
}

var errDao12aClose = errors.New("dao12a close error")

// dao12aCloser counts Close calls on the original body: a handler that swaps
// req.Body must still forward Close to it, with its error.
type dao12aCloser struct {
	io.Reader
	closes int
}

func (c *dao12aCloser) Close() error {
	c.closes++
	return errDao12aClose
}

func TestDao12a_G6(t *testing.T) {
	t.Run("BindParity", func(t *testing.T) {
		for _, tc := range []struct {
			name, body, message string
			excess, status      int
		}{
			{"CompleteBeforeEOF", `{"priority":9}`, "", 5, 200},
			{"SyntaxBeforeEOF", `{"priority":?}`, "invalid character '?' looking for beginning of value", 5, 400},
			{"Complete", `{"priority":9}`, "", 0, 200},
			{"TrailingJunk", `{"priority":9}oops`, "", 0, 200},
			{"TwoValues", `{"priority":9}{"priority":4}`, "", 0, 200},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := dao12aFixture(t, "webhook", false)
				w := dao12aRawRequest(t, s, tc.body, tc.excess)
				var response struct {
					Error string `json:"error"`
				}
				_ = json.Unmarshal(w.Body.Bytes(), &response)
				priority, writes := 9, "UpdateAction:10 Set:10"
				if tc.status == 400 {
					priority, writes = 1, ""
				}
				dao12aCheck(t, "Status", w.Code, tc.status)
				dao12aCheck(t, "Msg", response.Error, tc.message)
				dao12aCheck(t, "Priority", dao12aState(s, 10).Priority, priority)
				dao12aCheck(t, "Writes", dao12aWrites(s), writes)
			})
		}
	})
	t.Run("CloseForward", func(t *testing.T) {
		for _, tc := range []struct {
			name, body string
			status     int
		}{
			{"Success", `{"priority":9}`, 200},
			{"BindError", `{"priority":?}`, 400},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := dao12aFixture(t, "webhook", false)
				req := dao12aWire(t, tc.body, 0)
				original := &dao12aCloser{Reader: req.Body}
				req.Body = original
				w := dao12aServe(s, req)
				dao12aCheck(t, "Status", w.Code, tc.status)
				dao12aCheck(t, "ClosesDuring", original.closes, 0)
				err := req.Body.Close()
				dao12aCheck(t, "ClosesAfter", original.closes, 1)
				dao12aCheck(t, "CloseError", err, errDao12aClose)
			})
		}
	})
}

func dao12aRequest(t *testing.T, s *dao12aStore, method string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	r := setupTransactionRouter(s)
	if method == "create" {
		return postActionRaw(t, r, 1, body)
	}
	return putActionRaw(t, r, 10, body)
}
func TestDao12a_G4(t *testing.T) {
	for _, method := range []string{"create", "update"} {
		for _, kind := range []string{"bgp", "webhook", "shell", "xdrop"} {
			for _, delay := range []int{-1, 1441, 0, 1440} {
				t.Run(fmt.Sprintf("%s/%s/%d", method, kind, delay), func(t *testing.T) {
					s := dao12aFixture(t, kind, false)
					body := dao12aBody(kind)
					body["bgp_withdraw_delay_minutes"] = delay
					w := dao12aRequest(t, s, method, body)
					status := 200
					if method == "create" {
						status = 201
					}
					msg := ""
					if delay < 0 || delay > 1440 {
						status, msg = 400, "bgp_withdraw_delay_minutes must be between 0 and 1440"
						dao12aCheck(t, "NoWrite", dao12aWrites(s), "")
					}
					var response struct {
						Error string `json:"error"`
					}
					_ = json.Unmarshal(w.Body.Bytes(), &response)
					dao12aCheck(t, "Status", w.Code, status)
					dao12aCheck(t, "Msg", response.Error, msg)
				})
			}
		}
	}
}

func TestDao12a_G5(t *testing.T) {
	cases := []struct {
		name, kind, msg string
		change          map[string]any
	}{
		{"Phase", "webhook", "trigger_phase must be on_detected or on_expired", map[string]any{"trigger_phase": "wrong"}},
		{"ExpiredXDrop", "xdrop", "", map[string]any{"trigger_phase": "on_expired"}},
		{"ExpiredBGP", "bgp", "", map[string]any{"trigger_phase": "on_expired"}},
		{"ExpiredMode", "webhook", "on_expired only supports run_mode=once", map[string]any{"trigger_phase": "on_expired", "run_mode": "periodic"}},
		{"WebhookConnector", "webhook", "webhook action requires connector_id", map[string]any{"connector_id": nil}},
		{"ShellConnector", "shell", "shell action requires connector_id", map[string]any{"connector_id": nil}},
		{"BGPConnector", "bgp", "bgp action requires connector_id", map[string]any{"connector_id": nil}},
		{"RouteMapMissing", "bgp", "bgp action (on_detected) requires bgp_route_map", map[string]any{"bgp_route_map": ""}},
		{"RouteMapCharacters", "webhook", "bgp_route_map may only contain letters, digits, '_', '-', '.'", map[string]any{"bgp_route_map": "bad map"}},
		{"XDropRequired", "xdrop", "xdrop_action is required", map[string]any{"xdrop_action": ""}},
		{"XDropEnum", "xdrop", "xdrop_action must be one of: filter_l4, rate_limit, unblock", map[string]any{"xdrop_action": "bad"}},
		{"XDropFields", "xdrop", "xDrop filter/rate_limit action requires at least one match field (dst_ip, src_ip, dst_port, src_port, or protocol)", map[string]any{"xdrop_custom_payload": json.RawMessage(`{}`)}},
		{"RateMissing", "xdrop", "xDrop rate_limit action requires a positive rate_limit value", map[string]any{"xdrop_action": "rate_limit"}},
		{"RateZero", "xdrop", "xDrop rate_limit action requires a positive rate_limit value", map[string]any{"xdrop_action": "rate_limit", "xdrop_custom_payload": json.RawMessage(`{"dst_ip":"192.0.2.1","rate_limit":0}`)}},
		{"DelayLow", "xdrop", "unblock_delay_minutes must be between 0 and 1440", map[string]any{"unblock_delay_minutes": -1}},
		{"DelayHigh", "xdrop", "unblock_delay_minutes must be between 0 and 1440", map[string]any{"unblock_delay_minutes": 1441}},
		{"DelaySubtype", "xdrop", "unblock_delay_minutes is only valid for filter_l4 or rate_limit actions", map[string]any{"xdrop_action": "unblock", "unblock_delay_minutes": 1}},
		{"PayloadTemplate", "webhook", "xdrop_custom_payload contains unknown template variable {bad}", map[string]any{"xdrop_custom_payload": json.RawMessage(`{"dst_ip":"{bad}"}`)}},
		{"ShellTemplate", "webhook", "shell_extra_args contains unknown template variable {bad}", map[string]any{"shell_extra_args": "{bad}"}},
		{"GlobalErrorXDrop", "xdrop", "failed to check global prefix references: database error", nil},
		{"GlobalErrorBGP", "bgp", "failed to check global prefix references: database error", nil},
		{"GlobalRefXDrop", "xdrop", "This response is referenced by global prefix (0.0.0.0/0) rules — cannot add xDrop/BGP action", nil},
		{"GlobalRefBGP", "bgp", "This response is referenced by global prefix (0.0.0.0/0) rules — cannot add xDrop/BGP action", nil},
		{"ConnectorBeforeRouteMap", "bgp", "bgp action requires connector_id", map[string]any{"connector_id": nil, "bgp_route_map": ""}},
		{"RangeBeforeXDrop", "xdrop", "bgp_withdraw_delay_minutes must be between 0 and 1440", map[string]any{"bgp_withdraw_delay_minutes": -1, "xdrop_action": ""}},
		{"ActionEnum", "webhook", `action_type must be one of: xdrop, bgp, webhook, shell; got ""`, map[string]any{"action_type": ""}},
		{"RunModeEnum", "webhook", `run_mode must be one of: '', once, periodic, retry_until_success; got "bad"`, map[string]any{"run_mode": "bad"}},
	}
	for _, method := range []string{"create", "update"} {
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				s := dao12aFixture(t, tc.kind, false)
				body, status, msg := dao12aBody(tc.kind), 400, tc.msg
				for k, v := range tc.change {
					body[k] = v
				}
				if strings.HasPrefix(tc.name, "Expired") && tc.name != "ExpiredMode" {
					msg = "xDrop/BGP on_expired actions are auto-generated — create an on_detected action instead"
					if method == "update" {
						msg = "xDrop/BGP on_expired actions are auto-generated — edit the on_detected action instead"
					}
				}
				if strings.HasPrefix(tc.name, "GlobalError") {
					s.global, status = "error", 500
				}
				if strings.HasPrefix(tc.name, "GlobalRef") {
					s.global = "referenced"
				}
				w := dao12aRequest(t, s, method, body)
				var response struct {
					Error string `json:"error"`
				}
				_ = json.Unmarshal(w.Body.Bytes(), &response)
				dao12aCheck(t, "Status", w.Code, status)
				dao12aCheck(t, "Msg", response.Error, msg)
				dao12aCheck(t, "NoWrite", dao12aWrites(s), "")
			})
		}
	}
	for _, name := range []string{"NotFound", "AutoGenerated", "CrossTypeBeforeEnums"} {
		t.Run("update/"+name, func(t *testing.T) {
			s := dao12aFixture(t, "webhook", false)
			body, status, msg := map[string]any{"priority": 9}, 400, ""
			switch name {
			case "NotFound":
				s.responses.actions = nil
				status, msg = 404, "action not found"
			case "AutoGenerated":
				s.responses.actions[0].AutoGenerated = true
				msg = "auto-generated on_expired actions cannot be edited directly — edit the on_detected action instead"
			default:
				body["action_type"], body["run_mode"] = "invalid", "invalid"
				msg = "cannot change action_type via PUT — delete this action and create a new one instead"
			}
			w := dao12aRequest(t, s, "update", body)
			var response struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &response)
			dao12aCheck(t, "Status", w.Code, status)
			dao12aCheck(t, "Msg", response.Error, msg)
			dao12aCheck(t, "NoWrite", dao12aWrites(s), "")
		})
	}
}

func dao12aText(n ast.Node) string {
	var b bytes.Buffer
	_ = format.Node(&b, token.NewFileSet(), n)
	return b.String()
}
func dao12aCalls(n ast.Node, name string) []*ast.CallExpr {
	var calls []*ast.CallExpr
	if n == nil {
		return calls
	}
	ast.Inspect(n, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			switch f := c.Fun.(type) {
			case *ast.Ident:
				if f.Name == name {
					calls = append(calls, c)
				}
			case *ast.SelectorExpr:
				if f.Sel.Name == name {
					calls = append(calls, c)
				}
			}
		}
		return true
	})
	return calls
}

func TestDao12a_G5Shape(t *testing.T) {
	src, err := os.ReadFile("../api/responses.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "responses.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			funcs[fn.Name.Name] = fn
		}
	}
	moved := []string{
		"trigger_phase must be on_detected or on_expired", "xDrop/BGP on_expired actions are auto-generated — ",
		"on_expired only supports run_mode=once", " action requires connector_id",
		"bgp action (on_detected) requires bgp_route_map", "bgp_route_map may only contain letters, digits, '_', '-', '.'",
		"failed to check global prefix references: ", "This response is referenced by global prefix (0.0.0.0/0) rules — cannot add xDrop/BGP action",
	}
	count := func(n ast.Node, prefix string) int {
		total := 0
		ast.Inspect(n, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				value, _ := strconv.Unquote(lit.Value)
				if strings.HasPrefix(value, prefix) {
					total++
				}
			}
			return true
		})
		return total
	}
	for i, text := range moved {
		dao12aCheck(t, fmt.Sprintf("Unique%d", i+1), count(file, text), 1)
	}
	commonNames := []string{}
	for _, name := range []string{"createAction", "updateAction"} {
		t.Run(name, func(t *testing.T) {
			var closure *ast.FuncLit
			for _, stmt := range funcs[name].Body.List {
				if ret, ok := stmt.(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
					closure, _ = ret.Results[0].(*ast.FuncLit)
				}
			}
			if closure == nil {
				t.Errorf("handler return closure missing")
				return
			}
			var call *ast.CallExpr
			var guard *ast.IfStmt
			for _, stmt := range closure.Body.List {
				if branch, ok := stmt.(*ast.IfStmt); ok {
					if init, ok := branch.Init.(*ast.AssignStmt); ok && len(init.Rhs) == 1 {
						if candidate, ok := init.Rhs[0].(*ast.CallExpr); ok && len(candidate.Args) == 5 {
							if fn, ok := candidate.Fun.(*ast.Ident); ok && funcs[fn.Name] != nil {
								call, guard = candidate, branch
							}
						}
					}
				}
			}
			if call == nil {
				t.Errorf("G5.Shape: common validation call missing")
				return
			}
			commonNames = append(commonNames, call.Fun.(*ast.Ident).Name)
			args := []string{}
			for _, a := range call.Args {
				args = append(args, dao12aText(a))
			}
			want := []string{"c", "deps", "dto", "respID", `"create"`}
			if name == "updateAction" {
				want[3], want[4] = "old.ResponseID", `"edit"`
			}
			dao12aCheck(t, "Arguments", args, want)
			dao12aCheck(t, "Guard", dao12aText(guard.Cond), "status != 0")
			dao12aCheck(t, "Result", dao12aText(guard.Init), strings.Replace(dao12aText(call), call.Fun.(*ast.Ident).Name+"(", "status, msg := "+call.Fun.(*ast.Ident).Name+"(", 1))
			dao12aCheck(t, "EarlyReturn", dao12aText(guard.Body), "{\n\terrResponse(c, status, msg)\n\treturn\n}")
			enum := dao12aCalls(closure, "validateActionEnums")
			dao12aCheck(t, "AfterEnums", len(enum) == 1 && enum[0].Pos() < call.Pos(), true)
			if name == "updateAction" {
				cross := token.NoPos
				ast.Inspect(closure, func(n ast.Node) bool {
					if b, ok := n.(*ast.BinaryExpr); ok && dao12aText(b) == "dto.ActionType != old.ActionType" {
						cross = b.Pos()
					}
					return true
				})
				dao12aCheck(t, "AfterCrossType", cross != token.NoPos && cross < call.Pos(), true)
			}
			for _, method := range []string{"CreateAction", "UpdateAction", "Set", "SetPairedWith", "DeleteAction"} {
				for i, write := range dao12aCalls(closure, method) {
					dao12aCheck(t, fmt.Sprintf("Before%s%d", method, i), call.Pos() < write.Pos(), true)
				}
			}
			for i, text := range moved {
				dao12aCheck(t, fmt.Sprintf("Moved%d", i+1), count(closure, text), 0)
			}
		})
	}
	dao12aCheck(t, "Shared", len(commonNames) == 2 && commonNames[0] == commonNames[1], true)
	if len(commonNames) == 2 {
		common := funcs[commonNames[0]]
		calls := dao12aCalls(common, "validateActionTemplateVars")
		dao12aCheck(t, "TemplateCall", len(calls), 1)
		propagates := false
		ast.Inspect(common, func(n ast.Node) bool {
			if branch, ok := n.(*ast.IfStmt); ok && len(dao12aCalls(branch.Init, "validateActionTemplateVars")) == 1 {
				propagates = dao12aText(branch.Cond) == "err != nil" && dao12aText(branch.Body) == "{\n\treturn http.StatusBadRequest, err.Error()\n}"
			}
			return true
		})
		dao12aCheck(t, "TemplatePropagation", propagates, true)
	}
	dao12aCheck(t, "UnreachableRetained", count(funcs["validateXDropAction"], "unblock_delay_minutes is only valid for on_detected actions"), 1)
}
