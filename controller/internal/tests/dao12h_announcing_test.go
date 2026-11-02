package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/api"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

const dao12hInterval = 2 * time.Minute
const dao12hPositive = `{"metric":0,"network":"192.0.2.10/32","nexthops":[{"ip":"0.0.0.0"}],"origin":"IGP","path":"","pathFrom":"external","peerId":"(unspec)","prefix":"192.0.2.10","prefixLen":32,"version":1,"weight":32768}`

type dao12hRepo struct {
	store.BGPAnnouncementRepo
	writes, lists atomic.Int64
	failWrites    int64
	failList      int64
	listed        chan struct{}
}

func (r *dao12hRepo) MarkAnnounced(ctx context.Context, id, gen int) error {
	if r.writes.Add(1) <= r.failWrites {
		return dao5Fault
	}
	return r.BGPAnnouncementRepo.MarkAnnounced(ctx, id, gen)
}
func (r *dao12hRepo) ListByStatus(ctx context.Context, status string) ([]store.BGPAnnouncement, error) {
	if status == "announcing" && r.lists.Add(1) == r.failList {
		return nil, dao5Fault
	}
	rows, err := r.BGPAnnouncementRepo.ListByStatus(ctx, status)
	if r.listed != nil {
		select {
		case r.listed <- struct{}{}:
		default:
		}
	}
	return rows, err
}

type dao12hFixture struct {
	ms  *MockStore
	r   *dao12hRepo
	e   *action.Engine
	id  int
	dir string
	reg *prometheus.Registry
}

func dao12hQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func (f *dao12hFixture) put(t *testing.T, name, value string) {
	t.Helper()
	dao5bCheck(t, os.WriteFile(filepath.Join(f.dir, name), []byte(value), 0600))
}
func dao12hConfig(prefix string) string {
	af := "ipv4 unicast"
	if strings.Contains(prefix, ":") {
		af = "ipv6 unicast"
	}
	return fmt.Sprintf("router bgp 64512\n address-family %s\n  network %s route-map RTBH\n exit-address-family\n!\n", af, prefix)
}
func dao12hRIB(prefix string, paths ...string) string {
	return fmt.Sprintf(`{"routes":{%q:[%s]}}`, prefix, strings.Join(paths, ","))
}
func dao12hNew(t *testing.T, prefix string) *dao12hFixture {
	t.Helper()
	ms, _, _ := dao4Fixture("bgp", "once", "on_detected")
	f := &dao12hFixture{ms: ms, dir: t.TempDir(), reg: prometheus.NewRegistry()}
	// Each invocation records every command in order. Response files are programmable.
	script := "#!/bin/sh\ncd " + dao12hQuote(f.dir) + "\nwhile [ \"$#\" -gt 0 ]; do\n shift\n cmd=$1\n shift\n printf '%s\\n' \"$cmd\" >> commands\n if [ -f barrier ] && [ \"$cmd\" = \"$(cat barrier)\" ]; then\n  printf entered > ready\n  read gate < gate\n fi\n case \"$cmd\" in\n 'show running-config') [ ! -f fail-config ] || exit 1; cat config;;\n 'show bgp ipv4 unicast json') [ ! -f fail-rib ] || exit 1; cat rib4;;\n 'show bgp ipv6 unicast json') [ ! -f fail-rib ] || exit 1; cat rib6;;\n esac\ndone\n"
	path := filepath.Join(f.dir, "vtysh")
	dao5bCheck(t, os.WriteFile(path, []byte(script), 0700))
	f.put(t, "commands", "")
	f.put(t, "config", dao12hConfig(prefix))
	f.put(t, "rib4", dao12hRIB(prefix, dao12hPositive))
	f.put(t, "rib6", dao12hRIB(prefix, strings.ReplaceAll(dao12hPositive, "0.0.0.0", "::")))
	ms.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Enabled: true, VtyshPath: path, BGPASN: 64512}}
	ms.responses.actions[0].BGPConnectorID, ms.responses.actions[0].BGPRouteMap = intPtr(7), "RTBH"
	ms.attacks.attacks = []store.Attack{{ID: 20, DstIP: strings.Split(prefix, "/")[0], StartedAt: time.Now()}}
	a, err := ms.BGPAnnouncements().Attach(context.Background(), store.BGPAttachParams{Prefix: prefix, RouteMap: "RTBH", ConnectorID: 7, AttackID: 20, ActionID: intPtr(10)})
	dao5bCheck(t, err)
	f.id = a.AnnouncementID
	f.r = &dao12hRepo{BGPAnnouncementRepo: ms.BGPAnnouncements()}
	s := dao5bStore{Store: ms, anns: f.r}
	f.e = action.NewEngine(s, "auto")
	dao5bCheck(t, metrics.Register(f.reg, s, dao4Tracker(s, nil)))
	return f
}
func (f *dao12hFixture) row(t *testing.T) store.BGPAnnouncement {
	t.Helper()
	a, err := f.ms.BGPAnnouncements().Get(context.Background(), f.id)
	dao5bCheck(t, err)
	return *a
}
func (f *dao12hFixture) metric(t *testing.T, name, label string) float64 {
	t.Helper()
	fs, err := f.reg.Gather()
	dao5bCheck(t, err)
	for _, family := range fs {
		if family.GetName() == name {
			for _, m := range family.Metric {
				for _, l := range m.Label {
					if l.GetValue() == label {
						return m.GetCounter().GetValue()
					}
				}
			}
		}
	}
	t.Fatalf("missing metric %s{%s}", name, label)
	return 0
}
func (f *dao12hFixture) outcome(t *testing.T, label string) float64 {
	return f.metric(t, "xsight_bgp_announcing_reconcile_total", label)
}
func (f *dao12hFixture) commands(t *testing.T) []string {
	s := strings.TrimSpace(dao4Read(t, filepath.Join(f.dir, "commands")))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
func (f *dao12hFixture) readonly(t *testing.T) {
	t.Helper()
	for _, cmd := range f.commands(t) {
		dao11jWant(t, "R15.ReadOnlyCommand", cmd == "show running-config" || cmd == "show bgp ipv4 unicast json" || cmd == "show bgp ipv6 unicast json", true)
	}
}
func (f *dao12hFixture) start(t *testing.T) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); f.e.RunAnnouncingReconcile(ctx, dao12hInterval) }()
	synctest.Wait()
	t.Cleanup(func() { cancel(); <-done; f.readonly(t) })
	return cancel, done
}
func (f *dao12hFixture) absent(t *testing.T, name, outcome string) {
	t.Helper()
	before := f.outcome(t, outcome)
	f.start(t)
	dao11jAdvance(dao12hInterval)
	dao11jWant(t, name+".NoWrite", f.r.writes.Load(), int64(0))
	dao11jWant(t, name+".StillAnnouncing", f.row(t).Status, "announcing")
	dao11jWant(t, name+".OutcomeDelta", f.outcome(t, outcome)-before, float64(1))
}

func TestDao12h_R0_Fixed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms, e, id := dao12hR0(t)
		f := dao12hNew(t, "192.0.2.10/32")
		conn := f.ms.bgpConnectors.connectors[0]
		dao5bCheck(t, ms.BGPConnectors().Update(context.Background(), &conn))
		f.ms, f.e, f.id = ms, e, id
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go e.RunWithdrawingReconcile(ctx, dao12hInterval)
		f.start(t)
		dao11jAdvance(dao12hInterval)
		dao11jWant(t, "R0.Fixed.Active", f.row(t).Status, "active")
	})
}
func TestDao12h_R1_R2(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao12hNew(t, "192.0.2.10/32")
		a := f.row(t)
		attached, err := f.ms.BGPAnnouncements().ListAttacks(context.Background(), f.id)
		dao5bCheck(t, err)
		before := f.outcome(t, "announced")
		f.start(t)
		dao11jWant(t, "R1.FirstRound.ZeroCommands", len(f.commands(t)), 0)
		dao11jAdvance(dao12hInterval - time.Second)
		dao11jWant(t, "R2.ZeroCommands", len(f.commands(t)), 0)
		dao11jWant(t, "R2.Unchanged", reflect.DeepEqual(f.row(t), a), true)
		dao11jAdvance(time.Second)
		dao11jWant(t, "R1.Active", f.row(t).Status, "active")
		got := f.row(t)
		got.Status = a.Status
		dao11jWant(t, "R1.OtherFieldsUnchanged", reflect.DeepEqual(got, a), true)
		after, err := f.ms.BGPAnnouncements().ListAttacks(context.Background(), f.id)
		dao5bCheck(t, err)
		dao11jWant(t, "R1.AttachmentsUnchanged", reflect.DeepEqual(attached, after), true)
		dao11jWant(t, "R1.ExactCommands", strings.Join(f.commands(t), "|"), "show running-config|show bgp ipv4 unicast json")
		dao11jWant(t, "R1.AnnouncedDelta", f.outcome(t, "announced")-before, float64(1))
	})
}
func TestDao12h_R3(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao12hNew(t, "192.0.2.10/32")
		f.start(t)
		f.ms.bgpAnnouncements.mu.Lock()
		f.ms.bgpAnnouncements.announcements[0].Gen++
		f.ms.bgpAnnouncements.mu.Unlock()
		dao11jAdvance(dao12hInterval)
		dao11jWant(t, "R3.ZeroCommands", len(f.commands(t)), 0)
		dao11jWant(t, "R3.StillAnnouncing", f.row(t).Status, "announcing")
		dao11jAdvance(dao12hInterval)
		dao11jWant(t, "R3.NewGenerationActive", f.row(t).Status, "active")
	})
}
func TestDao12h_R4(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao12hNew(t, "192.0.2.10/32")
		f.put(t, "config", "")
		b := dao5CaptureLog(t)
		f.absent(t, "R4", "absent")
		for _, field := range []string{"ERROR", fmt.Sprintf("announcement_id=%d", f.id), "prefix=192.0.2.10/32", "route-map=RTBH", "connector=7", "attached attacks rely on this route"} {
			dao11jWant(t, "R4.Log."+field, strings.Contains(b.text(), field), true)
		}
		dao11jAdvance(dao12hInterval)
		dao11jWant(t, "R4.ObservationRetained", len(f.commands(t)), 4)
	})
}
func TestDao12h_R4c(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao12hNew(t, "192.0.2.10/32")
		f.put(t, "rib4", `{"routes":{}}`)
		f.absent(t, "R4c", "config_only")
	})
}
func TestDao12h_R5_R5c(t *testing.T) {
	good := dao12hConfig("192.0.2.10/32")
	for name, config := range map[string]string{
		"R5.WrongRouteMap":      strings.ReplaceAll(good, "RTBH", "OTHER"),
		"R5.OtherASN":           strings.ReplaceAll(good, "64512", "64513"),
		"R5.NoRouteMap":         strings.ReplaceAll(good, " route-map RTBH", ""),
		"R5.Multicast":          strings.ReplaceAll(good, "ipv4 unicast", "ipv4 multicast"),
		"R5.WrongAF":            strings.ReplaceAll(good, "ipv4 unicast", "ipv6 unicast"),
		"R5c.AfterExit":         strings.ReplaceAll(good, "  network", " exit-address-family\n  network"),
		"R5c.NextAF":            strings.ReplaceAll(good, "  network", " address-family ipv6 unicast\n  network"),
		"R5c.TopLevel":          strings.ReplaceAll(good, "  network", "!\nroute-map RTBH permit 10\n  network"),
		"R5c.CorrectSegment":    good,
		"R5c.UnindentedNetwork": "router bgp 64512\n address-family ipv4 unicast\nnetwork 192.0.2.10/32 route-map RTBH\n",
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao12hNew(t, "192.0.2.10/32")
				f.put(t, "config", config)
				if name == "R5c.CorrectSegment" {
					f.start(t)
					dao11jAdvance(dao12hInterval)
					dao11jWant(t, name+".Active", f.row(t).Status, "active")
				} else {
					f.absent(t, name, "absent")
				}
			})
		})
	}
}
func TestDao12h_R5r(t *testing.T) {
	p := dao12hPositive
	cases := map[string]string{
		"Weight0":          strings.ReplaceAll(p, `"weight":32768`, `"weight":0`),
		"WeightMissing":    strings.ReplaceAll(p, `,"weight":32768`, ""),
		"PathAS32768":      strings.ReplaceAll(strings.ReplaceAll(p, `"weight":32768`, `"weight":0`), `"path":""`, `"path":"32768"`),
		"PathNonEmpty":     strings.ReplaceAll(p, `"path":""`, `"path":"64513"`),
		"PathMissing":      strings.ReplaceAll(p, `"path":"",`, ""),
		"PeerNeighbor":     strings.ReplaceAll(p, "(unspec)", "192.0.2.1"),
		"PeerMissing":      strings.ReplaceAll(p, `"peerId":"(unspec)",`, ""),
		"PeerUppercase":    `{"weight":32768,"path":"","peerId":"(UNSPEC)","nexthops":[{"ip":"0.0.0.0"}]}`,
		"NexthopNeighbor":  strings.ReplaceAll(p, "0.0.0.0", "192.0.2.1"),
		"NexthopsEmpty":    strings.ReplaceAll(p, `[{"ip":"0.0.0.0"}]`, `[]`),
		"NexthopMixed":     strings.ReplaceAll(p, `[{"ip":"0.0.0.0"}]`, `[{"ip":"0.0.0.0"},{"ip":"192.0.2.1"}]`),
		"NexthopNoIP":      strings.ReplaceAll(p, `[{"ip":"0.0.0.0"}]`, `[{}]`),
		"SplitAcrossPaths": strings.ReplaceAll(p, "(unspec)", "192.0.2.1") + "," + strings.ReplaceAll(p, `"weight":32768`, `"weight":0`),
		"Positive":         p, "LocalPathSecond": strings.ReplaceAll(p, "(unspec)", "192.0.2.1") + "," + p,
		"ExtraFields":      strings.Replace(p, "{", `{"valid":true,"bestpath":{"overall":true},`, 1),
		"IPv6":             strings.ReplaceAll(p, "0.0.0.0", "::"),
		"NormalizedPrefix": strings.ReplaceAll(p, "0.0.0.0", "::"),
	}
	strictCases := map[string]string{
		"PeerAliasOverride":       `{"routes":{"192.0.2.10/32":[{"weight":32768,"path":"","peerId":"192.0.2.1","PeerID":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]}}`,
		"RemovedAliasOverride":    `{"routes":{"192.0.2.10/32":[{"removed":true,"Removed":false,"weight":32768,"path":"","peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]}}`,
		"PathAliasOverride":       `{"routes":{"192.0.2.10/32":[{"weight":32768,"path":"64513","Path":"","peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]}}`,
		"NexthopIPAlias":          `{"routes":{"192.0.2.10/32":[{"weight":32768,"path":"","peerId":"(unspec)","nexthops":[{"ip":"192.0.2.1","IP":"0.0.0.0"}]}]}}`,
		"RoutesAlias":             `{"routes":{"192.0.2.10/32":[{"weight":32768,"path":"","peerId":"192.0.2.1","nexthops":[{"ip":"0.0.0.0"}]}]},"Routes":{"192.0.2.10/32":[{"weight":32768,"path":"","peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]}}`,
		"DuplicatePeer":           `{"routes":{"192.0.2.10/32":[{"weight":32768,"path":"","peerId":"192.0.2.1","peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]}}`,
		"UnicodeFoldStale":        `{"routes":{"192.0.2.10/32":[{"weight":32768,"path":"","peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}],"stale":true,"ſtale":false}]}}`,
		"LoneAlias":               `{"routes":{"192.0.2.10/32":[{"weight":32768,"path":"","PeerID":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]}}`,
		"WeightAliasOverride":     `{"routes":{"192.0.2.10/32":[{"weight":0,"Weight":32768,"path":"","peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]}}`,
		"NexthopsAliasOverride":   `{"routes":{"192.0.2.10/32":[{"weight":32768,"path":"","peerId":"(unspec)","nexthops":[{"ip":"192.0.2.1"}],"Nexthops":[{"ip":"0.0.0.0"}]}]}}`,
		"HistoryAliasOverride":    `{"routes":{"192.0.2.10/32":[{"history":true,"History":false,"weight":32768,"path":"","peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]}}`,
		"RibFailureAliasOverride": `{"routes":{"192.0.2.10/32":[{"ribFailure":true,"RibFailure":false,"weight":32768,"path":"","peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]}}`,
	}
	for name := range strictCases {
		cases[name] = ""
	}
	for _, flag := range []string{"History", "Removed", "Stale", "RibFailure"} {
		cases[flag] = strings.Replace(p, "{", `{"`+strings.ToLower(flag[:1])+flag[1:]+`":true,`, 1)
	}
	for _, name := range []string{"OtherPrefixOnly", "RoutesMissing", "BadJSON"} {
		cases[name] = p
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				prefix, key, file := "192.0.2.10/32", "192.0.2.10/32", "rib4"
				positive := name == "Positive" || name == "LocalPathSecond" || name == "ExtraFields" || name == "IPv6" || name == "NormalizedPrefix"
				if name == "IPv6" || name == "NormalizedPrefix" {
					prefix, key, file = "2001:db8:12::/48", "2001:db8:12::/48", "rib6"
				}
				if name == "NormalizedPrefix" {
					key = "2001:0DB8:0012:0000:0000:0000:0000:0000/48"
				}
				if name == "OtherPrefixOnly" {
					key = "192.0.2.11/32"
				}
				f := dao12hNew(t, prefix)
				rib, outcome := dao12hRIB(key, path), "config_only"
				if name == "RoutesMissing" {
					rib = `{}`
				}
				if name == "BadJSON" {
					rib, outcome = "not JSON", "probe_error"
				}
				if raw, ok := strictCases[name]; ok {
					rib, outcome = raw, "probe_error"
				}
				f.put(t, file, rib)
				if positive {
					f.start(t)
					dao11jAdvance(dao12hInterval)
					dao11jWant(t, "R5r."+name+".Active", f.row(t).Status, "active")
				} else {
					before := f.outcome(t, "config_only")
					f.absent(t, "R5r."+name, outcome)
					if outcome == "probe_error" {
						dao11jWant(t, "R5r."+name+".NotConfigOnly", f.outcome(t, "config_only")-before, float64(0))
					}
				}
			})
		})
	}
}

func TestDao12h_R6(t *testing.T) {
	for _, file := range []string{"fail-config", "fail-rib"} {
		t.Run(file, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao12hNew(t, "192.0.2.10/32")
				f.put(t, file, "")
				f.absent(t, "R6."+file, "probe_error")
				dao5bCheck(t, os.Remove(filepath.Join(f.dir, file)))
				dao11jAdvance(dao12hInterval)
				dao11jWant(t, "R6.Recovered.Active", f.row(t).Status, "active")
			})
		})
	}
}
func TestDao12h_R7(t *testing.T) {
	for _, name := range []string{"R7", "R7d", "R7p"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao12hNew(t, "192.0.2.10/32")
				outcome := "skipped_disabled"
				switch name {
				case "R7":
					f.ms.bgpConnectors.connectors = nil
					outcome = "lookup_error"
				case "R7d":
					f.ms.bgpConnectors.connectors[0].Enabled = false
				case "R7p":
					f.ms.bgpConnectors.connectors[0].VtyshPath = ""
				}
				f.absent(t, name, outcome)
				dao11jWant(t, name+".ZeroCommands", len(f.commands(t)), 0)
			})
		})
	}
}
func (f *dao12hFixture) barrier(t *testing.T, command string) (func(), func()) {
	t.Helper()
	ready, gate := filepath.Join(f.dir, "ready"), filepath.Join(f.dir, "gate")
	for _, p := range []string{ready, gate} {
		dao5bCheck(t, unix.Mkfifo(p, 0600))
	}
	f.put(t, "barrier", command)
	entered := func() {
		r, err := os.Open(ready)
		if err != nil {
			t.Error(err)
			return
		}
		_, err = io.Copy(io.Discard, r)
		r.Close()
		if err != nil {
			t.Error(err)
		}
	}
	return entered, func() {
		dao5bCheck(t, os.Remove(filepath.Join(f.dir, "barrier")))
		dao5bCheck(t, os.WriteFile(gate, []byte("release\n"), 0600))
	}
}
func TestDao12h_R8(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao12hNew(t, "192.0.2.10/32")
		stale, failed := f.outcome(t, "stale"), f.outcome(t, "state_write_error")
		f.start(t)
		entered, release := f.barrier(t, "show bgp ipv4 unicast json")
		<-time.After(dao12hInterval)
		entered()
		a := f.row(t)
		d, err := f.ms.BGPAnnouncements().Detach(context.Background(), 20, a.Prefix, a.RouteMap, 7)
		dao5bCheck(t, err)
		dao11jWant(t, "R8.SameGenerationDetach", d.Gen == a.Gen && d.NeedWithdraw, true)
		release()
		synctest.Wait()
		dao11jWant(t, "R8.StaleDelta", f.outcome(t, "stale")-stale, float64(1))
		dao11jWant(t, "R8.NoStateWriteError", f.outcome(t, "state_write_error")-failed, float64(0))
		dao11jWant(t, "R8.DetachPreserved", f.row(t).Status, "withdrawing")
		dao11jWant(t, "R8.ExactCommands", strings.Join(f.commands(t), "|"), "show running-config|show bgp ipv4 unicast json")
	})
}
func TestDao12h_R9(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao12hNew(t, "192.0.2.10/32")
		f.r.failWrites = 3
		before, failed := f.outcome(t, "state_write_error"), f.metric(t, "xsight_state_write_failures_total", "bgp_ann_state")
		f.start(t)
		dao11jAdvance(dao12hInterval)
		dao11jWant(t, "R9.ThreeWriteAttempts", f.r.writes.Load(), int64(3))
		dao11jWant(t, "R9.StillAnnouncing", f.row(t).Status, "announcing")
		dao11jWant(t, "R9.OutcomeDelta", f.outcome(t, "state_write_error")-before, float64(1))
		dao11jWant(t, "R9.StateWriteFailuresDelta", f.metric(t, "xsight_state_write_failures_total", "bgp_ann_state")-failed, float64(1))
		dao11jAdvance(dao12hInterval)
		dao11jWant(t, "R9.Retry.Active", f.row(t).Status, "active")
		dao11jWant(t, "R9.Retry.Probed", len(f.commands(t)), 4)
	})
}
func TestDao12h_R10(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao12hNew(t, "192.0.2.10/32")
		cancel, done := f.start(t)
		cancel()
		synctest.Wait()
		dao11jWant(t, "R10.Exited", dao11jClosed(done), true)
	})
}
func TestDao12h_R11(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao12hNew(t, "192.0.2.10/32")
		f.r.failList = 2
		before := f.outcome(t, "list_error")
		f.start(t)
		dao11jAdvance(dao12hInterval)
		dao11jWant(t, "R11.ListErrorDelta", f.outcome(t, "list_error")-before, float64(1))
		dao11jWant(t, "R11.SecondRound.ZeroCommands", len(f.commands(t)), 0)
		dao11jAdvance(dao12hInterval)
		dao11jWant(t, "R11.ThirdRound.Probed", len(f.commands(t)), 2)
		dao11jWant(t, "R11.Active", f.row(t).Status, "active")
	})
}
func TestDao12h_R12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao12hNew(t, "192.0.2.10/32")
		second, err := f.ms.BGPAnnouncements().Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.11/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 21})
		dao5bCheck(t, err)
		f.put(t, "config", dao12hConfig("192.0.2.10/32")+dao12hConfig("192.0.2.11/32"))
		f.put(t, "rib4", fmt.Sprintf(`{"routes":{"192.0.2.10/32":[%s],"192.0.2.11/32":[%s]}}`, dao12hPositive, dao12hPositive))
		f.start(t)
		dao11jAdvance(dao12hInterval)
		a, err := f.ms.BGPAnnouncements().Get(context.Background(), second.AnnouncementID)
		dao5bCheck(t, err)
		dao11jWant(t, "R12.BothActive", a.Status == "active" && f.row(t).Status == "active", true)
		dao11jWant(t, "R12.TwoWrites", f.r.writes.Load(), int64(2))
		dao11jWant(t, "R12.FourCommands", len(f.commands(t)), 4)
	})
}
func TestDao12h_R13(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao12hNew(t, "2001:db8:12::/48")
		f.start(t)
		dao11jAdvance(dao12hInterval)
		dao11jWant(t, "R13.ExactAFCommand", strings.Join(f.commands(t), "|"), "show running-config|show bgp ipv6 unicast json")
		dao11jWant(t, "R13.Active", f.row(t).Status, "active")
	})
}
func TestDao12h_R14(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao12hNew(t, "192.0.2.10/32")
		f.ms.bgpAnnouncements.announcements, f.ms.bgpAnnouncements.attacks = nil, nil
		f.r.listed = make(chan struct{}, 1)
		entered, release := f.barrier(t, "network 192.0.2.10/32 route-map RTBH")
		start := time.Now()
		f.e.HandleEvent(tracker.AttackEvent{Type: "confirmed", DBID: 20, Attack: &store.Attack{ID: 20, DstIP: "192.0.2.10", ResponseID: intPtr(1), Direction: "receives", DecoderFamily: "udp"}})
		entered()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() { defer close(done); f.e.RunAnnouncingReconcile(ctx, dao12hInterval) }()
		<-f.r.listed
		release()
		synctest.Wait()
		dao11jWant(t, "R14.CompletedBeforeInterval", time.Since(start) < dao12hInterval, true)
		rows, err := f.ms.BGPAnnouncements().ListByStatus(context.Background(), "active")
		dao5bCheck(t, err)
		dao11jWant(t, "R14.AnnounceCompleted", len(rows), 1)
		for _, command := range f.commands(t) {
			dao11jWant(t, "R14.FirstRound.NoProbe", strings.HasPrefix(command, "show "), false)
		}
		f.put(t, "commands", "")
		dao11jAdvance(dao12hInterval)
		dao11jWant(t, "R14.NextRound.ZeroCommands", len(f.commands(t)), 0)
		cancel()
		<-done
		f.readonly(t)
	})
}
func TestDao12h_R16(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao12hNew(t, "192.0.2.10/32")
		_, err := f.ms.BGPAnnouncements().Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 21, ActionID: intPtr(10)})
		dao5bCheck(t, err)
		f.ms.attacks.attacks = append(f.ms.attacks.attacks, store.Attack{ID: 21, DstIP: "192.0.2.10", StartedAt: time.Now()})
		// There is no on_expired action: cleanup must traverse sweepEndedBGP.
		cancel, done := f.start(t)
		dao11jAdvance(dao12hInterval)
		cancel()
		<-done
		f.readonly(t)
		dao11jWant(t, "R16.SharedActive", f.row(t).Status == "active" && f.row(t).Refcount == 2, true)
		router := api.NewRouter(api.Dependencies{Store: f.ms, ActionEngine: f.e, JWTSecret: testJWTSecret})
		req := httptest.NewRequest("GET", "/api/active-actions/bgp", nil)
		req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		dao11jWant(t, "R16.API.OK", w.Code, 200)
		var response []api.ActiveResponseAction
		dao5bCheck(t, json.Unmarshal(w.Body.Bytes(), &response))
		found := false
		for _, a := range response {
			if a.AnnouncementID == f.id {
				found = true
			}
		}
		dao11jWant(t, "R16.API.Visible", found, true)
		f.put(t, "commands", "")
		for _, id := range []int{20, 21} {
			now := time.Now()
			f.ms.attacks.mu.Lock()
			for i := range f.ms.attacks.attacks {
				if f.ms.attacks.attacks[i].ID == id {
					f.ms.attacks.attacks[i].EndedAt = &now
				}
			}
			f.ms.attacks.mu.Unlock()
			f.e.HandleEvent(tracker.AttackEvent{Type: "expired", DBID: id, Attack: &store.Attack{ID: id, DstIP: "192.0.2.10", ResponseID: intPtr(1), EndedAt: &now}})
			synctest.Wait()
			if id == 20 {
				dao11jWant(t, "R16.First.RefcountOne", f.row(t).Refcount, 1)
				dao11jWant(t, "R16.First.Active", f.row(t).Status, "active")
				dao11jWant(t, "R16.First.NoWithdraw", len(f.commands(t)), 0)
				rows, err := f.ms.BGPAnnouncements().ListAttachmentsForAttack(context.Background(), id)
				dao5bCheck(t, err)
				dao11jWant(t, "R16.First.Detached", len(rows) == 0 || rows[0].DetachedAt != nil, true)
			}
		}
		dao11jWant(t, "R16.Last.OneWithdraw", strings.Count(strings.Join(f.commands(t), "\n"), "no network "), 1)
		dao11jWant(t, "R16.Last.LeavesActive", f.row(t).Status != "active", true)
		f.put(t, "commands", "")
	})
}
func TestDao12h_R17(t *testing.T) {
	// Sequential test: resetting first makes prior loop outcomes irrelevant.
	metrics.BGPAnnouncingReconcile.Reset()
	ms := NewMockStore()
	reg := prometheus.NewRegistry()
	dao5bCheck(t, metrics.Register(reg, ms, dao4Tracker(ms, nil)))
	fs, err := reg.Gather()
	dao5bCheck(t, err)
	got := map[string]bool{}
	for _, f := range fs {
		if f.GetName() == "xsight_bgp_announcing_reconcile_total" {
			for _, m := range f.Metric {
				for _, l := range m.Label {
					if l.GetName() == "outcome" {
						got[l.GetValue()] = true
					}
				}
			}
		}
	}
	for _, outcome := range []string{"list_error", "lookup_error", "skipped_disabled", "probe_error", "absent", "config_only", "announced", "stale", "state_write_error"} {
		dao11jWant(t, "R17.LabelExists."+outcome, got[outcome], true)
	}
	dao11jWant(t, "R17.NineLabels", len(got), 9)
}
func TestDao12h_G2(t *testing.T) {
	fs := token.NewFileSet()
	main, err := parser.ParseFile(fs, "../../main.go", nil, 0)
	dao5bCheck(t, err)
	render := func(n ast.Node) string {
		var b bytes.Buffer
		dao5bCheck(t, printer.Fprint(&b, fs, n))
		return b.String()
	}
	var eval func(ast.Expr) constant.Value
	eval = func(e ast.Expr) constant.Value {
		switch x := e.(type) {
		case *ast.BasicLit:
			return constant.MakeFromLiteral(x.Value, x.Kind, 0)
		case *ast.SelectorExpr:
			if render(x) == "time.Minute" {
				return constant.MakeInt64(int64(time.Minute))
			}
		case *ast.BinaryExpr:
			return constant.BinaryOp(eval(x.X), x.Op, eval(x.Y))
		}
		return constant.MakeUnknown()
	}
	constOK, wired := false, false
	ast.Inspect(main, func(n ast.Node) bool {
		if v, ok := n.(*ast.ValueSpec); ok {
			for i, name := range v.Names {
				if name.Name == "announcingReconcileInterval" {
					constOK = constant.Compare(eval(v.Values[i]), token.EQL, constant.MakeInt64(int64(2*time.Minute)))
				}
			}
		}
		return true
	})
	for _, decl := range main.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "main" {
			continue
		}
		recover, withdrawing, announcing := -1, -1, -1
		for i, stmt := range fn.Body.List {
			if expr, ok := stmt.(*ast.ExprStmt); ok {
				if call, ok := expr.X.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "recoverOnStartup" {
						recover = i
					}
				}
			}
			if g, ok := stmt.(*ast.GoStmt); ok {
				if s, ok := g.Call.Fun.(*ast.SelectorExpr); ok {
					if s.Sel.Name == "RunWithdrawingReconcile" {
						withdrawing = i
					}
					if s.Sel.Name == "RunAnnouncingReconcile" {
						announcing = i
						dao11jWant(t, "G2.Arguments", render(g.Call), "actionEngine.RunAnnouncingReconcile(ctx, announcingReconcileInterval)")
					}
				}
			}
		}
		wired = recover >= 0 && withdrawing > recover && announcing > recover
	}
	dao11jWant(t, "G2.IntervalTwoMinutes", constOK, true)
	dao11jWant(t, "G2.AnnouncingGoAfterRecovery", wired, true)
	f, err := parser.ParseFile(fs, "../action/announcing_reconcile.go", nil, 0)
	dao5bCheck(t, err)
	writes, shows := 0, 0
	ribExpression, err := parser.ParseExpr(`"show bgp "+addressFamilyForPrefix(ann.Prefix)+" json"`)
	dao5bCheck(t, err)
	noLocks := true
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			noLocks = noLocks && id.Name != "LockAnnouncement" && id.Name != "tryLockAnnouncement"
		}
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			s, err := strconv.Unquote(lit.Value)
			dao5bCheck(t, err)
			dao11jWant(t, "G2.NoConfigLiteral", !strings.Contains(s, "configure") && !strings.Contains(s, "network "), true)
		}
		if c, ok := n.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "runVtysh" {
				shows++
				arg := render(c.Args[2])
				dao11jWant(t, "G2.ShowExpression", arg == `"show running-config"` || arg == render(ribExpression), true)
			}
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok && strings.HasPrefix(render(sel.X), "e.store.") {
				allowed := sel.Sel.Name == "BGPAnnouncements" || sel.Sel.Name == "BGPConnectors" || sel.Sel.Name == "Get" || sel.Sel.Name == "ListByStatus" || sel.Sel.Name == "MarkAnnounced"
				dao11jWant(t, "G2.StoreMethod."+sel.Sel.Name, allowed, true)
				if sel.Sel.Name == "MarkAnnounced" {
					writes++
				}
			}
		}
		return true
	})
	dao11jWant(t, "G2.NoAnnouncementLocks", noLocks, true)
	dao11jWant(t, "G2.OneWriteMethod", writes, 1)
	dao11jWant(t, "G2.TwoShowSites", shows, 2)
}
