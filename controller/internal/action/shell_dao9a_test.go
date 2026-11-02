package action

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

const dao9aEchoArgsEnv = "XSIGHT_DAO9A_ECHO_ARGS"

// The child process echoes its actual argv before testing parses any flags.
func TestMain(m *testing.M) {
	if os.Getenv(dao9aEchoArgsEnv) == "1" {
		if err := json.NewEncoder(os.Stdout).Encode(os.Args[1:]); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// These fixtures are immutable after construction; unused repository methods
// deliberately retain their nil embedded interfaces.
type dao9aShellStore struct {
	store.Store
	repo dao9aShellRepo
}

func (s dao9aShellStore) ShellConnectors() store.ShellConnectorRepo { return s.repo }

type dao9aShellRepo struct {
	store.ShellConnectorRepo
	connector store.ShellConnector
}

func (r dao9aShellRepo) Get(_ context.Context, id int) (*store.ShellConnector, error) {
	if id != r.connector.ID {
		return nil, fmt.Errorf("unexpected connector id %d", id)
	}
	c := r.connector
	return &c, nil
}

func TestDao9aShellArgs(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const summary = `[{"node":"edge node 1","note":"say \"hello\""}]`
	cases := []struct {
		name     string
		defaults string
		extra    string
		nodes    []string
		fa       *FlowAnalysis
		want     []string
	}{
		{name: "H1", extra: "--data {flow_summary_json}", fa: &FlowAnalysis{FlowSummaryJSON: summary}, want: []string{"--data", summary}},
		{name: "H2", defaults: "-n {node_sources}", nodes: []string{"edge node 1"}, want: []string{"-n", "edge node 1"}},
		{name: "H5", extra: "--node {node_sources}", want: []string{"--node", ""}},
		{name: "H3", extra: `"a b" c`, want: []string{"a b", "c"}},
		{name: "H4/empty", want: []string{}},
		{name: "H4/spaces", defaults: "   ", extra: "   ", want: []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(dao9aEchoArgsEnv, "1")
			connector := store.ShellConnector{ID: 9, Name: "argv-echo", Command: executable, DefaultArgs: tc.defaults, Enabled: true}
			s := dao9aShellStore{repo: dao9aShellRepo{connector: connector}}
			act := store.ResponseAction{ID: 9, ShellConnectorID: &connector.ID, ShellExtraArgs: tc.extra}
			attack := &store.Attack{NodeSources: tc.nodes}
			log, err := executeShell(context.Background(), s, act, attack, "detected", "", "dao9a", "on_detected", 9, tc.fa)
			if err != nil {
				t.Fatalf("executeShell: %v; log = %+v", err, log)
			}
			if log == nil || log.Status != "success" {
				t.Fatalf("executeShell log = %+v, want success", log)
			}
			var got []string
			if err := json.Unmarshal([]byte(log.ResponseBody), &got); err != nil {
				t.Fatalf("decode echoed argv: %v; ResponseBody = %q", err, log.ResponseBody)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("script argv = %q, want %q", got, tc.want)
			}
			if tc.name == "H1" {
				if len(got) < 2 {
					t.Fatal("script received no JSON argument")
				}
				var decoded []map[string]string
				if err := json.Unmarshal([]byte(got[1]), &decoded); err != nil {
					t.Errorf("script JSON argument cannot unmarshal: %v; value = %q", err, got[1])
				}
			}
		})
	}
}

func TestDao9aCarpetBombEngine_G6a(t *testing.T) {
	for _, tc := range []struct {
		name string
		ip   string
		want bool
	}{
		{"subnet", "192.0.2.0/24", true},
		{"host", "192.0.2.1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := store.ActionPrecondition{Attribute: "carpet_bomb", Operator: "eq", Value: "true"}
			got := evaluateStructuredPrecondition(p, &store.Attack{DstIP: tc.ip}, "", nil)
			if got != tc.want {
				t.Errorf("carpet_bomb eq true for %s = %t, want %t", tc.ip, got, tc.want)
			}
		})
	}
}
