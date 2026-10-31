//go:build dao5b_lab

package postgres

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"golang.org/x/sys/unix"
)

// This opt-in test binary is the entire lab hook. Production binaries never
// compile it. It uses an isolated contract database and one fixed RFC 5737 /32.
const dao5bLabPrefix = "192.0.2.239/32"

type dao5bLabStore struct {
	store.Store
	repo *dao5bLabRepo
}

func (s dao5bLabStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.repo }

type dao5bLabRepo struct {
	store.BGPAnnouncementRepo
	announced      chan error
	beforeWithdraw func()
}

func (r *dao5bLabRepo) MarkAnnounced(c context.Context, id, gen int) error {
	err := r.BGPAnnouncementRepo.MarkAnnounced(c, id, gen)
	r.announced <- err
	return err
}
func (r *dao5bLabRepo) MarkFailedAnnounce(c context.Context, id, gen int, msg string) error {
	err := r.BGPAnnouncementRepo.MarkFailedAnnounce(c, id, gen, msg)
	r.announced <- fmt.Errorf("announce failed: %s; state write: %v", msg, err)
	return err
}
func (r *dao5bLabRepo) MarkWithdrawn(c context.Context, id, gen int) error {
	if r.beforeWithdraw != nil {
		r.beforeWithdraw()
	}
	return r.BGPAnnouncementRepo.MarkWithdrawn(c, id, gen)
}
func dao5bLabCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func dao5bLabCommand(t *testing.T, path, command string) []byte {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, err := exec.CommandContext(c, path, "-c", command).CombinedOutput()
	if err != nil {
		t.Fatalf("lab read command %q failed: %v", command, err)
	}
	return b
}

// dao5bLabPresent reports whether FRR's running-config carries the lab network
// statement. running-config changes when vtysh returns; the BGP table entry is
// pruned by bgpd asynchronously after "no network", so it can lag a withdrawal.
func dao5bLabPresent(t *testing.T, path string) bool {
	t.Helper()
	for _, line := range strings.Split(string(dao5bLabCommand(t, path, "show running-config")), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "network" && f[1] == dao5bLabPrefix {
			return true
		}
	}
	return false
}
func dao5bLabAwait(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(20 * time.Second):
		t.Fatal("lab completion notification missing")
	}
	return nil
}
func dao5bLabRun(t *testing.T, killed bool) {
	if os.Getenv("XSIGHT_DAO5B_LAB") != "1" {
		t.Fatal("lab requires explicit XSIGHT_DAO5B_LAB=1")
	}
	expected := os.Getenv("XSIGHT_DAO5B_LAB_EXPECT")
	if expected != "head" && expected != "fixed" {
		t.Fatal("XSIGHT_DAO5B_LAB_EXPECT must be head or fixed")
	}
	real := os.Getenv("XSIGHT_DAO5B_LAB_VTYSH")
	if !filepath.IsAbs(real) {
		t.Fatal("XSIGHT_DAO5B_LAB_VTYSH must be an absolute executable path")
	}
	asn, err := strconv.Atoi(os.Getenv("XSIGHT_DAO5B_LAB_ASN"))
	dao5bLabCheck(t, err)
	if asn <= 0 {
		t.Fatal("invalid lab ASN")
	}
	routeMap := os.Getenv("XSIGHT_DAO5B_LAB_ROUTE_MAP")
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(routeMap) {
		t.Fatal("invalid lab route-map")
	}
	config := string(dao5bLabCommand(t, real, "show running-config"))
	neighbors := 0
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "neighbor ") {
			neighbors++
		}
	}
	if neighbors != 0 {
		t.Fatalf("refusing lab: configured FRR neighbor count=%d", neighbors)
	}
	if !strings.Contains(config, fmt.Sprintf("router bgp %d\n", asn)) || !strings.Contains(config, "route-map "+routeMap+" ") {
		t.Fatal("lab ASN / route-map is not already configured")
	}
	if strings.Contains(config, dao5bLabPrefix) || dao5bLabPresent(t, real) {
		t.Fatal("refusing lab: document prefix already present")
	}
	t.Logf("LAB_GUARD prefix=%s configured_neighbors=%d", dao5bLabPrefix, neighbors)
	b := newPostgresContractBackend(t).(*postgresContractBackend)
	c := context.Background()
	conn := &store.BGPConnector{Name: "dao5b-lab", Enabled: true, VtyshPath: real, BGPASN: asn, AddressFamily: "ipv4 unicast"}
	conn.ID, err = b.db.BGPConnectors().Create(c, conn)
	dao5bLabCheck(t, err)
	r := &dao5bLabRepo{BGPAnnouncementRepo: b.db.BGPAnnouncements(), announced: make(chan error, 4)}
	s := dao5bLabStore{b.db, r}
	attach := func() (store.BGPAttachResult, error) {
		attack, err := b.db.Attacks().Create(c, &store.Attack{DstIP: "192.0.2.239", Direction: "receives", DecoderFamily: "udp", StartedAt: time.Now()})
		if err != nil {
			return store.BGPAttachResult{}, err
		}
		return r.Attach(c, store.BGPAttachParams{Prefix: dao5bLabPrefix, RouteMap: routeMap, ConnectorID: conn.ID, AttackID: attack})
	}
	first, err := attach()
	dao5bLabCheck(t, err)
	id := first.AnnouncementID
	// Teardown also uses the production withdrawal entry, never a hand-issued
	// vtysh mutation. It is registered after the database cleanup, hence runs first.
	t.Cleanup(func() {
		r.beforeWithdraw = nil
		_, gen, e := r.ForceWithdraw(c, id)
		if e != nil {
			t.Error(e)
			return
		}
		_, e = action.PerformBGPWithdrawForOrphan(c, s, conn, store.ResponseAction{}, dao5bLabPrefix, routeMap, id, gen)
		if e != nil {
			t.Error(e)
		}
		if dao5bLabPresent(t, real) {
			t.Error("lab cleanup left document prefix in FRR")
		}
	})
	announce := func() {
		action.NewEngine(s, "auto").ReconcileOnStartup(c)
		dao5bLabCheck(t, dao5bLabAwait(t, r.announced))
		if !dao5bLabPresent(t, real) {
			t.Fatal("production announcement did not create FRR prefix")
		}
	}
	announce()
	_, gen, err := r.ForceWithdraw(c, id)
	dao5bLabCheck(t, err)
	caller, cancel := context.WithTimeout(c, time.Second)
	defer cancel()
	withdrawalConn := *conn
	var entered <-chan struct{}
	if killed {
		dir := t.TempDir()
		ready := filepath.Join(dir, "ready")
		gate := filepath.Join(dir, "gate")
		dao5bLabCheck(t, unix.Mkfifo(ready, 0600))
		dao5bLabCheck(t, unix.Mkfifo(gate, 0600))
		quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
		path := filepath.Join(dir, "vtysh")
		body := "#!/bin/sh\nprintf ready > " + quote(ready) + "\nread release < " + quote(gate) + "\nexec " + quote(real) + " \"$@\"\n"
		dao5bLabCheck(t, os.WriteFile(path, []byte(body), 0700))
		withdrawalConn.VtyshPath = path
		notification := make(chan struct{})
		entered = notification
		go func() {
			f, e := os.Open(ready)
			if e != nil {
				return
			}
			_, _ = io.Copy(io.Discard, f)
			_ = f.Close()
			close(notification)
		}()
	} else {
		// Called after real vtysh success, immediately before the repository write.
		r.beforeWithdraw = cancel
	}
	done := make(chan error, 1)
	go func() {
		_, e := action.PerformBGPWithdrawForOrphan(caller, s, &withdrawalConn, store.ResponseAction{}, dao5bLabPrefix, routeMap, id, gen)
		done <- e
	}()
	if entered != nil {
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("vtysh did not reach FIFO barrier")
		}
	}
	err = dao5bLabAwait(t, done)
	if killed && err == nil {
		t.Error("L1a expected vtysh process failure")
	}
	if !killed {
		dao5bLabCheck(t, err)
	}
	if caller.Err() == nil {
		t.Error("caller context remained live")
	}
	r.beforeWithdraw = nil
	row, err := r.Get(c, id)
	dao5bLabCheck(t, err)
	want := "withdrawn"
	if killed {
		want = "failed"
	}
	if expected == "head" {
		want = "withdrawing"
	}
	if row == nil || row.Status != want {
		t.Fatalf("lab terminal row=%+v; want %s", row, want)
	}
	present := dao5bLabPresent(t, real)
	if !killed && present {
		t.Fatal("L1b successful withdrawal left FRR prefix")
	}
	next, attachErr := attach()
	if expected == "head" {
		if attachErr == nil {
			t.Errorf("HEAD unexpectedly attached new attack: %+v", next)
		}
		t.Logf("LAB_RESULT expected=head terminal=%s new_attack_blocked=%v prefix_present=%v", row.Status, attachErr != nil, present)
		return
	}
	dao5bLabCheck(t, attachErr)
	if !next.NeedAnnounce {
		t.Fatal("new attack did not request announcement")
	}
	announce()
	t.Logf("LAB_RESULT expected=fixed terminal=%s new_attack_need_announce=true prefix_present=true gen=%d", row.Status, next.Gen)
}
func TestDao5b_L1a(t *testing.T) { dao5bLabRun(t, true) }
func TestDao5b_L1b(t *testing.T) { dao5bLabRun(t, false) }
