package api

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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

func TestDao12b_G3(t *testing.T) {
	for _, tc := range []struct {
		name, body, route, output string
		status                    int
	}{
		{"TestHang.Exec", "exec sleep 30", "test", "", 502},
		{"TestHang.Child", "sleep 30; :", "test", "", 502},
		{"RoutesBothHang", "sleep 30; :", "routes", "", 502},
		{"Routes4HangOK6", "case \"$*\" in *ipv4*) exec sleep 30;; *) echo route6;; esac", "routes", "route6\n", 200},
		{"Routes6HangOK4", "case \"$*\" in *ipv6*) exec sleep 30;; *) echo route4;; esac", "routes", "route4\n", 200},
		{"BgOK", "sleep 30 &\necho ok", "test", "ok\n", 200},
		{"HeldThenDeadline", "sleep 30 &\necho ok", "test", "ok\n", 200},
		{"NonZero", "echo broken\nexit 3", "test", "", 502},
		{"Normal.Test", "printf '%s\\n' \"$@\"", "test", "-c\nshow bgp summary\n", 200},
		{"Normal.Routes", "printf '%s\\n' \"$@\"", "routes", "-c\nshow ip bgp ipv4 unicast\n\n--- IPv6 ---\n-c\nshow ip bgp ipv6 unicast\n", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, wait := vtyshHTTPTimeout, vtyshHTTPWaitDelay
			vtyshHTTPTimeout, vtyshHTTPWaitDelay = 300*time.Millisecond, 200*time.Millisecond
			t.Cleanup(func() { vtyshHTTPTimeout, vtyshHTTPWaitDelay = old, wait })
			if tc.name == "HeldThenDeadline" {
				vtyshHTTPWaitDelay = 500 * time.Millisecond
			}
			path, record := dao12bScript(t, tc.body)
			s := dao11cFixture()
			s.bgps.rows = []store.BGPConnector{{ID: 7, Enabled: true, BGPASN: 64512, VtyshPath: path}}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Params = gin.Params{{Key: "id", Value: "7"}}
			method := "POST"
			if tc.route == "routes" {
				method = "GET"
			}
			c.Request = httptest.NewRequest(method, "/api/settings/bgp-connectors/7/"+tc.route, nil)
			d, timely := dao12bAwait(t, path, 2*time.Second, func() {
				if tc.route == "routes" {
					listBGPRoutes(Dependencies{Store: s})(c)
				} else {
					testBGPConnector(Dependencies{Store: s})(c)
				}
			})
			var response struct {
				Output string `json:"output"`
				OK     bool   `json:"ok"`
				Error  string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			dao12bWant(t, "G3."+tc.name, timely && w.Code == tc.status && response.Output == tc.output, w.Body.String())
			switch tc.name {
			case "TestHang.Exec", "TestHang.Child":
				dao12bWant(t, "G3."+tc.name+".Timeout", strings.Contains(w.Body.String(), "timed out") && d < 900*time.Millisecond, d)
			case "RoutesBothHang":
				dao12bWant(t, "G3.RoutesBothHang.Text", strings.Contains(response.Error, "ipv4=") && strings.Contains(response.Error, "ipv6=") && strings.Count(response.Error, "timed out") == 2, response.Error)
				dao12bWant(t, "G3.RoutesBothHang.Total", timely && d < 900*time.Millisecond, d)
			case "BgOK":
				dao12bWant(t, "G3.BgOK.Fast", timely && d < 400*time.Millisecond, d)
			case "HeldThenDeadline":
				dao12bWant(t, "G3.HeldThenDeadline.Crossed", d >= 300*time.Millisecond, d)
			case "NonZero":
				dao12bWant(t, "G3.NonZero.Text", response.Error == "vtysh failed: exit status 3\nbroken", response.Error)
			case "Normal.Test", "Normal.Routes":
				b, _ := os.ReadFile(record)
				if tc.route == "test" {
					dao12bWant(t, "G3.Normal.Test.Args", string(b) == tc.output && response.OK, string(b))
				} else {
					dao12bWant(t, "G3.Normal.Routes.Args", strings.Count(string(b), "-c\n") == 2 && strings.Contains(string(b), "show ip bgp ipv4 unicast") && strings.Contains(string(b), "show ip bgp ipv6 unicast"), string(b))
				}
			}
		})
	}
}
