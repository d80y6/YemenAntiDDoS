package threshold

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type dao13aTreeStore struct {
	store.Store
	prefixes []store.WatchPrefix
	rules    []store.Threshold
}
type dao13aTreePrefixes struct {
	store.PrefixRepo
	rows []store.WatchPrefix
}
type dao13aTreeRules struct {
	store.ThresholdRepo
	rows []store.Threshold
}

func (s dao13aTreeStore) Prefixes() store.PrefixRepo                           { return dao13aTreePrefixes{rows: s.prefixes} }
func (s dao13aTreeStore) Thresholds() store.ThresholdRepo                      { return dao13aTreeRules{rows: s.rules} }
func (r dao13aTreePrefixes) List(context.Context) ([]store.WatchPrefix, error) { return r.rows, nil }
func (r dao13aTreeRules) List(context.Context) ([]store.Threshold, error)      { return r.rows, nil }
func dao13aInt(n int) *int                                                     { return &n }
func dao13aPrefix(id int, parent *int) store.WatchPrefix {
	return store.WatchPrefix{ID: id, Prefix: fmt.Sprintf("10.%d.0.0/16", id), ParentID: parent, Enabled: true}
}

func TestDao13a_C1(t *testing.T) {
	for _, name := range []string{"SelfCycle", "TwoNodeCycle", "ThreeNodeCycle", "OutsideChild", "LongChain", "MissingParent", "DisabledParent"} {
		t.Run(name, func(t *testing.T) {
			if os.Getenv("XSIGHT_DAO13A_TREE_CHILD") == name {
				dao13aTreeChild(t, name)
				return
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestDao13a_C1$/^"+name+"$", "-test.v")
			cmd.Env = append(os.Environ(), "XSIGHT_DAO13A_TREE_CHILD="+name)
			output, timedOut, err := dao13aTreeProcess(t, cmd)
			if !bytes.Contains(output, []byte("DAO13A_BEFORE_REBUILD")) {
				t.Fatalf("subprocess did not reach Rebuild: %v\n%s", err, output)
			}
			if timedOut {
				t.Fatalf("Rebuild subprocess exceeded real-time deadline\n%s", output)
			}
			if err != nil {
				t.Fatalf("Rebuild subprocess failed: %v\n%s", err, output)
			}
			t.Logf("Rebuild subprocess returned:\n%s", output)
		})
	}
}

func dao13aTreeChild(t *testing.T, name string) {
	t.Helper()
	s := dao13aTreeStore{}
	chains := map[int][]int{}
	switch name {
	case "SelfCycle":
		s.prefixes = []store.WatchPrefix{dao13aPrefix(1, dao13aInt(1))}
		chains[1] = []int{1}
	case "TwoNodeCycle":
		s.prefixes = []store.WatchPrefix{dao13aPrefix(1, dao13aInt(2)), dao13aPrefix(2, dao13aInt(1))}
		chains = map[int][]int{1: {1, 2}, 2: {2, 1}}
	case "ThreeNodeCycle":
		s.prefixes = []store.WatchPrefix{dao13aPrefix(1, dao13aInt(2)), dao13aPrefix(2, dao13aInt(3)), dao13aPrefix(3, dao13aInt(1))}
		chains = map[int][]int{1: {1, 2, 3}, 2: {2, 3, 1}, 3: {3, 1, 2}}
	case "OutsideChild":
		s.prefixes = []store.WatchPrefix{dao13aPrefix(1, dao13aInt(2)), dao13aPrefix(2, dao13aInt(1)), dao13aPrefix(3, dao13aInt(1)), dao13aPrefix(4, dao13aInt(3))}
		chains = map[int][]int{1: {1, 2}, 2: {2, 1}, 3: {3, 1, 2}, 4: {4, 3, 1, 2}}
		s.rules = []store.Threshold{{ID: 30, PrefixID: dao13aInt(3), Domain: "internal_ip", Direction: "receives", Decoder: "udp", Unit: "pps", Comparison: "over", Value: 300, Inheritable: true, Enabled: true}}
	case "MissingParent":
		s.prefixes = []store.WatchPrefix{dao13aPrefix(1, dao13aInt(99))}
	case "DisabledParent":
		s.prefixes = []store.WatchPrefix{dao13aPrefix(1, nil), dao13aPrefix(2, dao13aInt(1))}
		s.prefixes[0].Enabled = false
		s.rules = []store.Threshold{{ID: 30, PrefixID: dao13aInt(1), Domain: "internal_ip", Direction: "receives", Decoder: "udp", Unit: "pps", Value: 300, Inheritable: true, Enabled: true}}
	case "LongChain":
		s = dao13aLongChain()
	}
	tree := NewTree()
	for rebuild := 0; rebuild < 2; rebuild++ {
		var logs bytes.Buffer
		func() {
			old := log.Writer()
			log.SetOutput(&logs)
			defer log.SetOutput(old)
			fmt.Println("DAO13A_BEFORE_REBUILD")
			if err := tree.Rebuild(context.Background(), s); err != nil {
				t.Fatal(err)
			}
		}()
		errors := 0
		for _, line := range strings.Split(logs.String(), "\n") {
			if strings.Contains(line, "ERROR") {
				errors++
			}
		}
		if errors != len(chains) {
			t.Fatalf("rebuild %d ERROR lines=%d; want %d\n%s", rebuild, errors, len(chains), logs.String())
		}
		for id, chain := range chains {
			needle := fmt.Sprintf("prefix_id=%d chain=%v", id, chain)
			if strings.Count(logs.String(), needle) != 1 {
				t.Errorf("rebuild %d needs one log for %q:\n%s", rebuild, needle, logs.String())
			}
		}
		switch name {
		case "OutsideChild":
			want := engine.ResolvedThreshold{ThresholdID: 30, PrefixID: 4, Prefix: "10.4.0.0/16", Domain: "internal_ip", Direction: "receives", Decoder: "udp", Unit: "pps", Comparison: "over", Value: 300}
			dao13aResolvedEqual(t, tree.ForPrefix("10.4.0.0/16"), []engine.ResolvedThreshold{want})
		case "DisabledParent":
			if len(tree.ForPrefix("10.1.0.0/16")) != 0 {
				t.Error("disabled parent must not produce rules for itself")
			}
			want := engine.ResolvedThreshold{ThresholdID: 30, PrefixID: 2, Prefix: "10.2.0.0/16", Domain: "internal_ip", Direction: "receives", Decoder: "udp", Unit: "pps", Value: 300}
			dao13aResolvedEqual(t, tree.ForPrefix("10.2.0.0/16"), []engine.ResolvedThreshold{want})
		case "MissingParent":
			for _, p := range s.prefixes {
				if len(tree.ForPrefix(p.Prefix)) != 0 {
					t.Errorf("truncated parent leaked rules for %s", p.Prefix)
				}
			}
		case "LongChain":
			dao13aLongOracle(t, tree)
		}
	}
}

func dao13aLongChain() dao13aTreeStore {
	s := dao13aTreeStore{}
	for id := 1; id <= 5; id++ {
		var parent *int
		if id > 1 {
			parent = dao13aInt(id - 1)
		}
		s.prefixes = append(s.prefixes, dao13aPrefix(id, parent))
	}
	s.prefixes[0].ThresholdTemplateID = dao13aInt(101)
	s.prefixes[4].ThresholdTemplateID = dao13aInt(105)
	add := func(id int, template, prefix *int, decoder, unit, direction, domain string, value int64, inherit bool) {
		s.rules = append(s.rules, store.Threshold{ID: id, TemplateID: template, PrefixID: prefix,
			Decoder: decoder, Unit: unit, Direction: direction, Domain: domain, Comparison: "over",
			Value: value, Inheritable: inherit, Enabled: true, ResponseID: dao13aInt(1000 + id)})
	}
	add(1, dao13aInt(101), nil, "udp", "pps", "receives", "internal_ip", 100, true)
	add(2, dao13aInt(101), nil, "tcp", "pps", "receives", "internal_ip", 200, false)
	add(3, dao13aInt(101), nil, "icmp", "pps", "receives", "internal_ip", 300, true)
	add(4, dao13aInt(101), nil, "udp", "bps", "sends", "subnet", 400, true)
	add(5, dao13aInt(105), nil, "udp", "pps", "receives", "internal_ip", 500, true)
	add(6, dao13aInt(105), nil, "tcp_syn", "pps", "receives", "internal_ip", 600, false)
	add(7, nil, dao13aInt(1), "udp", "pps", "receives", "internal_ip", 700, true)
	add(8, nil, dao13aInt(1), "fragment", "pps", "receives", "internal_ip", 800, false)
	add(9, nil, dao13aInt(5), "udp", "pps", "receives", "internal_ip", 900, true)
	add(10, nil, dao13aInt(5), "icmp", "pps", "receives", "internal_ip", 0, true)
	add(11, dao13aInt(105), nil, "udp", "bps", "sends", "subnet", 1100, true)
	add(12, nil, dao13aInt(1), "gre", "pps", "receives", "internal_ip", 1200, true)
	add(13, dao13aInt(105), nil, "gre", "pps", "receives", "internal_ip", 1300, true)
	return s
}

func dao13aLongOracle(t *testing.T, tree *Tree) {
	t.Helper()
	// Explicit expected winners, independent of the inheritance implementation.
	winners := map[int][]int{1: {2, 3, 4, 7, 8, 12}, 2: {3, 4, 7, 12}, 3: {3, 4, 7, 12}, 4: {3, 4, 7, 12}, 5: {6, 9, 11, 12}}
	specs := map[int]engine.ResolvedThreshold{
		2:  {ThresholdID: 2, Decoder: "tcp", Unit: "pps", Direction: "receives", Domain: "internal_ip", Comparison: "over", Value: 200, ResponseID: dao13aInt(1002)},
		3:  {ThresholdID: 3, Decoder: "icmp", Unit: "pps", Direction: "receives", Domain: "internal_ip", Comparison: "over", Value: 300, ResponseID: dao13aInt(1003)},
		4:  {ThresholdID: 4, Decoder: "udp", Unit: "bps", Direction: "sends", Domain: "subnet", Comparison: "over", Value: 400, ResponseID: dao13aInt(1004)},
		6:  {ThresholdID: 6, Decoder: "tcp_syn", Unit: "pps", Direction: "receives", Domain: "internal_ip", Comparison: "over", Value: 600, ResponseID: dao13aInt(1006)},
		7:  {ThresholdID: 7, Decoder: "udp", Unit: "pps", Direction: "receives", Domain: "internal_ip", Comparison: "over", Value: 700, ResponseID: dao13aInt(1007)},
		8:  {ThresholdID: 8, Decoder: "fragment", Unit: "pps", Direction: "receives", Domain: "internal_ip", Comparison: "over", Value: 800, ResponseID: dao13aInt(1008)},
		9:  {ThresholdID: 9, Decoder: "udp", Unit: "pps", Direction: "receives", Domain: "internal_ip", Comparison: "over", Value: 900, ResponseID: dao13aInt(1009)},
		11: {ThresholdID: 11, Decoder: "udp", Unit: "bps", Direction: "sends", Domain: "subnet", Comparison: "over", Value: 1100, ResponseID: dao13aInt(1011)},
		12: {ThresholdID: 12, Decoder: "gre", Unit: "pps", Direction: "receives", Domain: "internal_ip", Comparison: "over", Value: 1200, ResponseID: dao13aInt(1012)},
	}
	for id, ids := range winners {
		prefix := fmt.Sprintf("10.%d.0.0/16", id)
		var want []engine.ResolvedThreshold
		for _, rule := range ids {
			r := specs[rule]
			r.PrefixID, r.Prefix = id, prefix
			want = append(want, r)
		}
		dao13aResolvedEqual(t, tree.ForPrefix(prefix), want)
	}
}

func dao13aResolvedEqual(t *testing.T, got, want []engine.ResolvedThreshold) {
	t.Helper()
	index := func(rows []engine.ResolvedThreshold) map[[4]string]engine.ResolvedThreshold {
		out := map[[4]string]engine.ResolvedThreshold{}
		for _, r := range rows {
			key := [4]string{r.Decoder, r.Unit, r.Direction, r.Domain}
			if _, exists := out[key]; exists {
				t.Fatalf("duplicate resolved key %v", key)
			}
			out[key] = r
		}
		return out
	}
	if !reflect.DeepEqual(index(got), index(want)) {
		t.Errorf("resolved result=%+v; want %+v", got, want)
	}
}

func TestDao13a_R0_Fixed_P1_08(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestDao13a_C1$/^SelfCycle$", "-test.v")
	cmd.Env = append(os.Environ(), "XSIGHT_DAO13A_TREE_CHILD=SelfCycle")
	out, timedOut, err := dao13aTreeProcess(t, cmd)
	if err != nil || timedOut || !bytes.Contains(out, []byte("DAO13A_BEFORE_REBUILD")) {
		t.Fatalf("self-cycle did not return cleanly: err=%v timeout=%v\n%s", err, timedOut, out)
	}
}

type dao13aProcessOutput struct {
	mu     sync.Mutex
	data   bytes.Buffer
	marker chan struct{}
	once   sync.Once
}

func (w *dao13aProcessOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.data.Write(p)
	if bytes.Contains(w.data.Bytes(), []byte("DAO13A_BEFORE_REBUILD")) {
		w.once.Do(func() { close(w.marker) })
	}
	return n, err
}

// Separate startup from the bounded Rebuild interval. Always kill and reap a
// timed-out child; the short post-marker deadline bounds the buggy chain's memory.
func dao13aTreeProcess(t *testing.T, cmd *exec.Cmd) ([]byte, bool, error) {
	t.Helper()
	output := &dao13aProcessOutput{marker: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = output, output
	cmd.Env = append(cmd.Env, "GOMEMLIMIT=32MiB", "GORACE=atexit_sleep_ms=0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	startup := time.NewTimer(10 * time.Second)
	defer startup.Stop()
	var err error
	timedOut := false
	select {
	case <-output.marker:
		deadline := time.NewTimer(250 * time.Millisecond)
		defer deadline.Stop()
		select {
		case err = <-done:
		case <-deadline.C:
			timedOut = true
			_ = cmd.Process.Kill()
			err = <-done
		}
	case err = <-done:
	case <-startup.C:
		_ = cmd.Process.Kill()
		err = <-done
		t.Fatalf("subprocess never reached Rebuild: %v", err)
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	return append([]byte(nil), output.data.Bytes()...), timedOut, err
}
