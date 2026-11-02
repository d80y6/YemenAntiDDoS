package action

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func dao12bWant(t *testing.T, name string, yes bool, detail any) {
	t.Helper()
	if !yes {
		t.Errorf("ASSERT %s FAIL %v", name, detail)
	} else {
		t.Logf("ASSERT %s PASS %v", name, detail)
	}
}

// The sleep shim execs the real sleep in the same PID, preserving every process tree.
func dao12bScript(t *testing.T, body string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	pids, record := filepath.Join(dir, "pids"), filepath.Join(dir, "calls")
	for name, text := range map[string]string{
		"sleep": "#!/bin/sh\necho $$ >> " + q(pids) + "\nexec /bin/sleep \"$@\"\n",
		"vtysh": "#!/bin/sh\nPATH=" + q(dir) + ":$PATH\necho $$ >> " + q(pids) + "\nprintf '%s\\n' \"$@\" >> " + q(record) + "\n" + body + "\n",
	} {
		text = strings.Replace(text, "#!/bin/sh\n", "#!/bin/sh\nif [ \"$1\" = --dao12b-prime ]; then exit 0; fi\n", 1)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0700); err != nil {
			t.Fatal(err)
		}
		if err := exec.Command(filepath.Join(dir, name), "--dao12b-prime").Run(); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "vtysh"), record
}

// Kill only PIDs recorded by this fixture; join execution before restoring globals.
func dao12bAwait(t *testing.T, path string, limit time.Duration, call func()) (time.Duration, bool) {
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
	for {
		pids, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "pids"))
		alive := false
		for _, field := range strings.Fields(string(pids)) {
			pid, err := strconv.Atoi(field)
			if err != nil || pid <= 1 {
				t.Fatalf("invalid fixture PID: %q", field)
			}
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
			panic("fixture cleanup watchdog: execution or recorded process still alive")
		}
	}
	t.Logf("CLEANUP joined=true recorded_processes_alive=0 elapsed=%s timely=%t", elapsed, timely)
	return elapsed, timely
}

func dao12bLimit(t *testing.T) {
	old, wait := vtyshTimeout, vtyshWaitDelay
	vtyshTimeout, vtyshWaitDelay = 300*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { vtyshTimeout, vtyshWaitDelay = old, wait })
}
func TestDao12b_G1(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"G1a", "exec sleep 30"}, {"G1b", "sleep 30; :"}, {"G1c", "exec sleep 30"},
		{"G1d", "sleep 30 &\necho ok"}, {"G1i", "sleep 30 &\necho ok"},
		{"G1f", "sleep 30 &\nexit 3"}, {"G1f.FastNonZero", "exit 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dao12bLimit(t)
			path, _ := dao12bScript(t, tc.body)
			ctx := context.Background()
			if tc.name == "G1c" {
				vtyshTimeout = 10 * time.Second
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			var out string
			var err error
			d, timely := dao12bAwait(t, path, 2*time.Second, func() { out, err = runVtysh(ctx, path, "show bgp summary") })
			switch tc.name {
			case "G1a", "G1b":
				dao12bWant(t, tc.name+".Returns", timely && d < time.Second, d)
				if tc.name == "G1a" {
					dao12bWant(t, "G1a.Text", errors.Is(err, errVtyshTimeout) && strings.Contains(err.Error(), "vtysh timed out"), err)
				}
			case "G1c":
				dao12bWant(t, "G1c.Parent", timely && d < 400*time.Millisecond, d)
			case "G1d", "G1i":
				name := "G1d.BgOK"
				if tc.name == "G1i" {
					name = "G1i.HeldThenDeadline"
				}
				dao12bWant(t, name, timely && d < time.Second && err == nil && strings.Contains(out, "ok"), err)
				if tc.name == "G1i" {
					dao12bWant(t, name+".Crossed", d >= 300*time.Millisecond, d)
				}
			case "G1f":
				var exit *exec.ExitError
				dao12bWant(t, "G1f.NonZeroHeld", timely && err != nil && errors.Is(err, errVtyshTimeout) && errors.As(err, &exit) && exit.ExitCode() == 3, err)
				dao12bWant(t, "G1f.NotEarly", d >= 300*time.Millisecond, d)
			case "G1f.FastNonZero":
				var exit *exec.ExitError
				dao12bWant(t, tc.name, timely && d < 200*time.Millisecond && errors.As(err, &exit) && exit.ExitCode() == 3 && !errors.Is(err, errVtyshTimeout), err)
			}
		})
	}
	t.Run("G1e.Fast", func(t *testing.T) {
		dao12bLimit(t)
		path, record := dao12bScript(t, "printf '  ok  \\n'")
		for _, p := range []string{"/usr/bin/true", path} {
			var out string
			var err error
			_, timely := dao12bAwait(t, p, 2*time.Second, func() { out, err = runVtysh(context.Background(), p, " show one \n\n show two ") })
			want := "ok"
			if p == "/usr/bin/true" {
				want = ""
			}
			dao12bWant(t, "G1e.Fast", timely && err == nil && out == want, out)
		}
		b, _ := os.ReadFile(record)
		dao12bWant(t, "G1e.Fast.Args", string(b) == "-c\nshow one\n-c\nshow two\n", string(b))
	})
	t.Run("G1h.ForceRemoveTimeout", func(t *testing.T) {
		dao12bLimit(t)
		s, act, _ := dao3BGPFixture(t)
		path, _ := dao12bScript(t, "echo 'no network 192.0.2.0/24'\nexec sleep 30")
		s.conn.VtyshPath = path
		var err error
		_, timely := dao12bAwait(t, path, 2*time.Second, func() {
			err = NewEngine(s, "auto").ForceRemove(context.Background(), 20, act.ID, 7, "192.0.2.0/24|RTBH")
		})
		dao12bWant(t, "G1h.ForceRemoveTimeout", timely && err != nil && strings.Contains(err.Error(), "vtysh timed out"), err)
	})
}

// Track non-nil error dominance and the preceding nil-error early return.
func TestDao12b_G1g_ErrGuard(t *testing.T) {
	_, headErr := os.Stat("dao12b_head_shim_test.go")
	for _, tc := range []struct{ path, fn, sentinel string }{
		{"bgp.go", "runVtysh", "errVtyshTimeout"}, {"../api/bgp_connector.go", "runVtyshHTTP", "errVtyshHTTPTimeout"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), tc.path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		count, valid, successNil, doubleWrap := 0, true, false, false
		var scan func([]ast.Stmt, bool, bool)
		scan = func(list []ast.Stmt, guarded, after bool) {
			for _, stmt := range list {
				if branch, ok := stmt.(*ast.IfStmt); ok {
					b, ok := branch.Cond.(*ast.BinaryExpr)
					nilGuard := false
					if ok {
						x, xok := b.X.(*ast.Ident)
						y, yok := b.Y.(*ast.Ident)
						nilGuard = xok && yok && x.Name == "err" && y.Name == "nil"
					}
					scan(branch.Body.List, guarded || (nilGuard && b.Op == token.NEQ), after)
					if branch.Else != nil {
						scan([]ast.Stmt{branch.Else}, guarded, after)
					}
					if nilGuard && b.Op == token.EQL {
						if ret, ok := branch.Body.List[len(branch.Body.List)-1].(*ast.ReturnStmt); ok {
							guarded, after = true, true
							// The success branch must return a literal nil error and must not re-read a context.
							last, _ := ret.Results[len(ret.Results)-1].(*ast.Ident)
							rereads := false
							ast.Inspect(branch.Body, func(n ast.Node) bool {
								if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Err" {
									rereads = true
								}
								return true
							})
							successNil = last != nil && last.Name == "nil" && !rereads
						}
					}
					continue
				}
				if block, ok := stmt.(*ast.BlockStmt); ok {
					scan(block.List, guarded, after)
					continue
				}
				ast.Inspect(stmt, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Errorf" {
						return true
					}
					pkg, ok := sel.X.(*ast.Ident)
					if !ok || pkg.Name != "fmt" {
						return true
					}
					hasSentinel, hasErr := false, false
					for _, arg := range call.Args {
						if id, ok := arg.(*ast.Ident); ok && id.Name == tc.sentinel {
							hasSentinel = true
							count++
							valid = valid && guarded && after
						}
						if id, ok := arg.(*ast.Ident); ok && id.Name == "err" {
							hasErr = true
						}
					}
					if lit, ok := call.Args[0].(*ast.BasicLit); ok && hasSentinel {
						doubleWrap = hasErr && strings.Count(lit.Value, "%w") == 2
					}
					return true
				})
			}
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == tc.fn {
				scan(fn.Body.List, false, false)
			}
		}
		if headErr == nil && count == 0 {
			t.Logf("ASSERT G1g.ErrGuard.%s PASS N/A HEAD has no timeout wrapper", tc.fn)
			continue
		}
		dao12bWant(t, "G1g.ErrGuard."+tc.fn, count == 1 && valid, count)
		dao12bWant(t, "G1g.SuccessNil."+tc.fn, successNil, successNil)
		dao12bWant(t, "G1g.DoubleWrap."+tc.fn, doubleWrap, doubleWrap)
	}
}

type dao12bBootstrap struct {
	*dao3BGPStore
	conns dao12bConns
	repo  *dao12bAnns
}
type dao12bConns struct {
	store.BGPConnectorRepo
	rows []store.BGPConnector
}

func (r dao12bConns) List(context.Context) ([]store.BGPConnector, error) { return r.rows, nil }

type dao12bAnns struct {
	store.BGPAnnouncementRepo
	writes int
}

func (r *dao12bAnns) HasOperationalHistory(context.Context) (bool, error) { return true, nil }
func (r *dao12bAnns) UpsertOrphan(context.Context, string, string, int, string) (bool, error) {
	r.writes++
	return true, nil
}
func (s dao12bBootstrap) BGPConnectors() store.BGPConnectorRepo       { return s.conns }
func (s dao12bBootstrap) BGPAnnouncements() store.BGPAnnouncementRepo { return s.repo }
func TestDao12b_G2(t *testing.T) {
	t.Run("Recover", func(t *testing.T) {
		dao12bLimit(t)
		s, _, _ := dao3BGPFixture(t)
		path, record := dao12bScript(t, "exec sleep 30")
		s.conn.VtyshPath = path
		s.ann.rows = []store.BGPAnnouncement{
			{ID: 1, Prefix: "192.0.2.0/24", RouteMap: "RTBH", ConnectorID: 7, Status: "active", Refcount: 1},
			{ID: 2, Prefix: "198.51.100.0/24", RouteMap: "RTBH", ConnectorID: 7, Status: "active", Refcount: 1},
		}
		before := append([]store.BGPAnnouncement(nil), s.ann.rows...)
		d, timely := dao12bAwait(t, path, 3*time.Second, func() { RecoverBGPRoutes(context.Background(), s) })
		b, _ := os.ReadFile(record)
		dao12bWant(t, "G2.Recover", timely && d < 3*time.Second, d)
		dao12bWant(t, "G2.Prefixes", strings.Contains(string(b), "network 192.0.2.0/24") && strings.Contains(string(b), "network 198.51.100.0/24"), string(b))
		dao12bWant(t, "G2.RowsUnchanged", reflect.DeepEqual(before, s.ann.rows) && len(s.ann.failures) == 0, s.ann.rows)
	})
	for _, name := range []string{"G2.V4", "G2.V5"} {
		t.Run(name, func(t *testing.T) {
			dao12bLimit(t)
			body := "exec sleep 30"
			if name == "G2.V5" {
				body = "case \"$*\" in *'show running-config'*) printf 'router bgp 64512\\n network 192.0.2.0/24 route-map RTBH\\n';; *) exec sleep 30;; esac"
			}
			path, record := dao12bScript(t, body)
			second, probe := dao12bScript(t, "exit 0")
			s := dao12bBootstrap{conns: dao12bConns{rows: []store.BGPConnector{{ID: 1, Enabled: true, BGPASN: 64512, VtyshPath: path}}}, repo: &dao12bAnns{}}
			if name == "G2.V4" {
				s.conns.rows = append(s.conns.rows, store.BGPConnector{ID: 2, Enabled: true, BGPASN: 64512, VtyshPath: second})
			}
			d, timely := dao12bAwait(t, path, 2*time.Second, func() { BootstrapBGPOrphans(context.Background(), s) })
			dao12bWant(t, name, timely && d < 2*time.Second && s.repo.writes == 0, d)
			b, _ := os.ReadFile(record)
			if name == "G2.V4" {
				b, _ = os.ReadFile(probe)
			}
			want := "show bgp ipv6 unicast"
			dao12bWant(t, name+".Probed", strings.Contains(string(b), want), string(b))
		})
	}
}
