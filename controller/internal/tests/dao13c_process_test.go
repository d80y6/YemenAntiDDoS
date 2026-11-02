package tests

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
)

func dao13cQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

// Every long-lived fixture process records its PID, including inherited pipes.
func dao13cProcess(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	pids := filepath.Join(dir, "pids")
	for name, text := range map[string]string{
		"sleep":  "#!/bin/sh\necho $$ >> " + dao13cQuote(pids) + "\nexec /bin/sleep \"$@\"\n",
		"script": "#!/bin/sh\nPATH=" + dao13cQuote(dir) + ":$PATH\necho $$ >> " + dao13cQuote(pids) + "\nprintf '%s\\n' \"$@\" >> " + dao13cQuote(filepath.Join(dir, "calls")) + "\n" + body + "\n",
	} {
		text = strings.Replace(text, "#!/bin/sh\n", "#!/bin/sh\nif [ \"$1\" = --dao13c-prime ]; then exit 0; fi\n", 1)
		path := filepath.Join(dir, name)
		dao5bCheck(t, os.WriteFile(path, []byte(text), 0700))
		dao5bCheck(t, exec.Command(path, "--dao13c-prime").Run())
	}
	return filepath.Join(dir, "script")
}

// A bounded wait is the assertion; killing and joining are unconditional cleanup.
func dao13cAwait(t *testing.T, path string, limit time.Duration, call func()) (time.Duration, bool) {
	t.Helper()
	done := make(chan time.Duration, 1)
	start := time.Now()
	go func() { call(); done <- time.Since(start) }()
	var elapsed time.Duration
	finished, timely := false, true
	select {
	case elapsed = <-done:
		finished = true
	case <-time.After(limit):
		timely = false
	}
	watch := time.NewTimer(10 * time.Second)
	defer watch.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	recorded := map[int]bool{}
	for {
		pids, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "pids"))
		alive := false
		for _, field := range strings.Fields(string(pids)) {
			pid, err := strconv.Atoi(field)
			if err != nil || pid <= 1 {
				t.Fatalf("invalid fixture PID %q", field)
			}
			recorded[pid] = true
			if err := syscall.Kill(pid, 0); err == nil {
				alive = true
				if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
					t.Fatal(err)
				}
			} else if err != syscall.ESRCH {
				t.Fatal(err)
			}
		}
		if finished && !alive {
			break
		}
		select {
		case elapsed = <-done:
			finished = true
		case <-tick.C:
		case <-watch.C:
			panic("dao13c cleanup watchdog: execution or fixture process still alive")
		}
	}
	t.Logf("CLEANUP joined=true recorded_processes=%d alive=0 elapsed=%s timely=%t", len(recorded), elapsed, timely)
	return elapsed, timely
}

type dao13cShellRepo struct {
	store.ShellConnectorRepo
	conn store.ShellConnector
}

func (r dao13cShellRepo) Get(context.Context, int) (*store.ShellConnector, error) {
	c := r.conn
	return &c, nil
}

type dao13cShellLookup struct {
	store.ShellConnectorRepo
	delay     time.Duration
	remaining chan time.Duration
}

func (r dao13cShellLookup) Get(c context.Context, id int) (*store.ShellConnector, error) {
	if r.delay > 0 {
		// Controlled input: connector lookup consumes some of the parent budget.
		timer := time.NewTimer(r.delay)
		defer timer.Stop()
		<-timer.C
	}
	conn, err := r.ShellConnectorRepo.Get(c, id)
	deadline, _ := c.Deadline()
	r.remaining <- time.Until(deadline)
	return conn, err
}

type dao13cShellStore struct {
	store.Store
	shell store.ShellConnectorRepo
	logs  store.ActionExecLogRepo
}

func (s dao13cShellStore) ShellConnectors() store.ShellConnectorRepo { return s.shell }
func (s dao13cShellStore) ActionExecLog() store.ActionExecLogRepo    { return s.logs }

func dao13cShellFixture(t *testing.T, path string, budget int, phase string) (*MockStore, *action.Engine, tracker.AttackEvent, <-chan store.ActionExecutionLog) {
	t.Helper()
	ms, _, ev := dao4Fixture("shell", "once", phase)
	ms.responses.actions[0].ShellConnectorID = intPtr(7)
	done := make(chan store.ActionExecutionLog, 8)
	s := dao13cShellStore{
		Store: ms,
		shell: dao13cShellRepo{ms.ShellConnectors(), store.ShellConnector{ID: 7, Name: "dao13c-shell", Enabled: true, Command: path, TimeoutMs: budget}},
		logs:  dao5bLogRepo{ms.ActionExecLog(), done},
	}
	return ms, action.NewEngine(s, "auto"), ev, done
}

func TestDao13c_S1(t *testing.T) {
	cases := []struct {
		name, script, status, message string
		budget                        int
		limit                         time.Duration
		lookupDelay                   time.Duration
	}{
		{"ForegroundSuccess", "exit 0", "success", "", 30000, 3 * time.Second, 0},
		{"ForegroundTimeout", "sleep 60", "timeout", "", 100, 4 * time.Second, 0},
		{"ConnectorDeadlineIsTimeout", "sleep 60", "timeout", "", 100, 4 * time.Second, 0},
		{"BackgroundOutput.Success", "sleep 60 &\nexit 0", "success", "background process held output; output truncated", 30000, 3 * time.Second, 0},
		{"DefaultBudgetTimeout", "sleep 60", "timeout", "", 0, 34 * time.Second, 0},
		{"ParentDeadlineIsTimeout", "sleep 60", "timeout", "", 60000, 34 * time.Second, 0},
		{"ParentBudgetSpent.Lookup10ms", "sleep 60", "timeout", "", 60000, 34 * time.Second, 10 * time.Millisecond},
		{"NonzeroAndBackground.Failed", "sleep 60 &\nexit 7", "failed", "exit status 7", 30000, 3 * time.Second, 0},
		{"BackgroundAndForegroundTimeout", "sleep 60 &\nsleep 60", "timeout", "", 100, 4 * time.Second, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := dao13cProcess(t, tc.script)
			ms, _, ev, _ := dao13cShellFixture(t, path, tc.budget, "on_detected")
			done := make(chan store.ActionExecutionLog, 1)
			remaining := make(chan time.Duration, 1)
			shell := dao13cShellRepo{ms.ShellConnectors(), store.ShellConnector{ID: 7, Name: "dao13c-shell", Enabled: true, Command: path, TimeoutMs: tc.budget}}
			e := action.NewEngine(dao13cShellStore{ms,
				dao13cShellLookup{shell, tc.lookupDelay, remaining},
				dao5bLogRepo{ms.ActionExecLog(), done}}, "auto")
			logs := dao5CaptureLog(t)
			var entry store.ActionExecutionLog
			elapsed, timely := dao13cAwait(t, path, tc.limit, func() {
				e.HandleEvent(ev)
				entry = <-done
			})
			t.Logf("RESULT S1.%s ErrorMessage=%q elapsed=%s", tc.name, entry.ErrorMessage, elapsed)
			dao11jWant(t, "S1."+tc.name+".Bounded", timely, true)
			dao11jWant(t, "S1."+tc.name+".Status", entry.Status, tc.status)
			if tc.status == "timeout" {
				// Engine action contexts have a 30-second parent deadline. A
				// positive connector timeout can shorten that nominal budget.
				nominal := 30 * time.Second
				if tc.budget > 0 {
					nominal = min(nominal, time.Duration(tc.budget)*time.Millisecond)
				}
				match := regexp.MustCompile(`^command timed out after (-?\d+)ms$`).FindStringSubmatch(entry.ErrorMessage)
				if len(match) != 2 {
					t.Errorf("ASSERT S1.%s.BudgetFormat FAIL ErrorMessage=%q", tc.name, entry.ErrorMessage)
				} else {
					value, err := strconv.ParseInt(match[1], 10, 64)
					dao5bCheck(t, err)
					// Setup before Run (lookup, command build) stays far below
					// one second; the whole-call elapsed time would include the
					// command's own runtime and make the lower bound vacuous.
					setupAllowance := time.Second + tc.lookupDelay
					lower, upper := (nominal - setupAllowance).Milliseconds(), nominal.Milliseconds()
					if value < lower || value > upper {
						t.Errorf("ASSERT S1.%s.BudgetRange FAIL ErrorMessage=%q nominal=%s elapsed=%s interval=[%d,%d]", tc.name, entry.ErrorMessage, nominal, elapsed, lower, upper)
					} else {
						t.Logf("ASSERT S1.%s.BudgetRange PASS value=%d interval=[%d,%d]", tc.name, value, lower, upper)
					}
					if tc.lookupDelay > 0 {
						// This independent clock reading precedes command setup.
						// It also rejects a constant nominal-budget message.
						left := <-remaining
						bound := (left + time.Millisecond).Milliseconds()
						if value > bound {
							t.Errorf("ASSERT S1.%s.SpentBudgetDeducted FAIL ErrorMessage=%q after_lookup_upper=%d", tc.name, entry.ErrorMessage, bound)
						} else {
							t.Logf("ASSERT S1.%s.SpentBudgetDeducted PASS value=%d after_lookup_upper=%d", tc.name, value, bound)
						}
					}
				}
				// executeAction logs executeShell's returned error before
				// publishing the execution row used as this fixture's barrier.
				wantError := fmt.Sprintf("action: shell failed for attack %d: %v", ev.DBID, context.DeadlineExceeded)
				dao11jWant(t, "S1."+tc.name+".ContextError", strings.Contains(logs.text(), wantError), true)
			} else {
				dao11jWant(t, "S1."+tc.name+".Message", strings.Contains(entry.ErrorMessage, tc.message), true)
			}
			if tc.status == "success" && tc.message != "" {
				dao11jWant(t, "S1.BackgroundOutput.Success", entry.Status, "success")
			}
		})
	}
}

func TestDao13c_S2(t *testing.T) {
	path := dao13cProcess(t, "sleep 60 &\nexit 0")
	ms, _, ev, _ := dao13cShellFixture(t, path, 30000, "on_expired")
	done := make(chan store.ActionExecutionLog, 8)
	withdrawn := make(chan struct{})
	s := dao13cShellStore{ms,
		dao13cShellRepo{ms.ShellConnectors(), store.ShellConnector{ID: 7, Name: "dao13c-shell", Enabled: true, Command: path, TimeoutMs: 30000}},
		dao5bLogRepo{ms.ActionExecLog(), done}}
	e := action.NewEngine(dao13cStore{s, dao13cSweepRepo{ms.BGPAnnouncements(), withdrawn}}, "auto")
	c := context.Background()
	ms.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Name: "dao13c", Enabled: true, VtyshPath: "/usr/bin/true", BGPASN: 65000}}
	attached, err := ms.BGPAnnouncements().Attach(c, store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 20})
	dao5bCheck(t, err)
	dao5bCheck(t, ms.BGPAnnouncements().MarkAnnounced(c, attached.AnnouncementID, attached.Gen))
	ev.Type = "expired"
	end := time.Now()
	ev.Attack.EndedAt = &end
	ms.attacks.expiredAttacks = []store.Attack{*ev.Attack}
	var shell store.ActionExecutionLog
	_, timely := dao13cAwait(t, path, 5*time.Second, func() {
		e.HandleEvent(ev)
		shell = <-done
		<-withdrawn
	})
	dao11jWant(t, "S2.SweepBounded", timely, true)
	dao11jWant(t, "S2.ShellSuccess", shell.ActionType == "shell" && shell.Status == "success", true)
	row, err := ms.BGPAnnouncements().Get(c, attached.AnnouncementID)
	dao5bCheck(t, err)
	dao11jWant(t, "S2.Withdrawn", row.Status, "withdrawn")
}

type dao13cSweepRepo struct {
	store.BGPAnnouncementRepo
	done chan struct{}
}

func (r dao13cSweepRepo) MarkWithdrawn(c context.Context, id, gen int) error {
	err := r.BGPAnnouncementRepo.MarkWithdrawn(c, id, gen)
	close(r.done)
	return err
}
