package postgres

import (
	"bytes"
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/metrics"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	dto "github.com/prometheus/client_model/go"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func dao13dOldBGP(t *testing.T, db *PGStore) {
	t.Helper()
	if _, err := db.pool.Exec(context.Background(), "DROP TABLE bgp_announcement_events, bgp_announcement_attacks, bgp_announcements CASCADE"); err != nil {
		t.Fatal(err)
	}
	t.Log("Old-schema simulation tests gates, first backfill and reentry only.")
}
func TestDao13d_P11_E(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://u@192.0.2.1:5432/x")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	c, cancel := context.WithCancel(context.Background())
	cancel()
	s := &PGStore{pool: pool}
	var logs bytes.Buffer
	prior := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prior)
	for _, which := range []string{"retention", "compression"} {
		logs.Reset()
		table := "ts_stats"
		if which == "retention" {
			s.removeRetentionPolicy(c, table)
		} else {
			table = "flow_logs"
			s.removeCompressionPolicy(c, table)
		}
		got := logs.String()
		for _, part := range []string{"WARNING", table, "context canceled", "NOT in effect"} {
			if !strings.Contains(got, part) {
				t.Errorf("P11-E %s missing %q: %s", which, part, got)
			}
		}
		if strings.Count(got, "\n") != 1 || strings.Contains(got, " none (") {
			t.Errorf("P11-E unexpected success or log count: %s", got)
		}
		t.Logf("P11-E raw log: %s", got)
	}
}

type dao13dFixture struct {
	t            *testing.T
	db           *PGStore
	c            context.Context
	cid          int
	path, record string
}

func dao13dCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func dao13dWant(t *testing.T, name string, ok bool) {
	t.Helper()
	if !ok {
		t.Fatalf("ASSERT %s FAIL", name)
	}
	t.Logf("ASSERT %s PASS", name)
}
func dao13dNew(t *testing.T) *dao13dFixture {
	t.Helper()
	f := &dao13dFixture{t: t, db: newPostgresContractBackend(t).(*postgresContractBackend).db, c: context.Background()}
	dir := t.TempDir()
	f.path = filepath.Join(dir, "vtysh")
	f.record = filepath.Join(dir, "commands")
	f.script("", false, false)
	conn := &store.BGPConnector{Name: "dao13d", Enabled: true, VtyshPath: f.path, BGPASN: 64512, AddressFamily: "ipv4 unicast"}
	var err error
	f.cid, err = f.db.BGPConnectors().Create(f.c, conn)
	dao13dCheck(t, err)
	t.Cleanup(func() { f.dump() })
	return f
}
func (f *dao13dFixture) exec(q string, args ...any) {
	f.t.Helper()
	_, err := f.db.pool.Exec(f.c, q, args...)
	dao13dCheck(f.t, err)
}
func (f *dao13dFixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	dao13dCheck(f.t, f.db.pool.QueryRow(f.c, q, args...).Scan(&n))
	return n
}
func (f *dao13dFixture) dump() {
	f.t.Helper()
	for _, table := range []string{"bgp_announcements", "bgp_announcement_attacks", "bgp_announcement_events", "attacks", "action_execution_log", "webhooks", "webhook_connectors", "xdrop_active_rules", "action_manual_overrides", "timescaledb_information.jobs"} {
		var raw string
		err := f.db.pool.QueryRow(f.c, "SELECT COALESCE(jsonb_agg(to_jsonb(r)), '[]'::jsonb)::text FROM "+table+" r").Scan(&raw)
		f.t.Logf("RAW %s rows=%s err=%v", table, raw, err)
	}
}
func (f *dao13dFixture) migrate(ret RetentionConfig) {
	f.t.Helper()
	dao13dCheck(f.t, f.db.AutoMigrate(f.c, ret))
}
func dao13dRetention() RetentionConfig {
	return RetentionConfig{TSStatsDays: 7, TSStatsCompressDays: 1, TSStatsCaggDays: 90, FlowLogsDays: 7, FlowLogsCompressDays: 1}
}
func (f *dao13dFixture) attack(ended bool) int {
	f.t.Helper()
	id, err := f.db.Attacks().Create(f.c, &store.Attack{DstIP: "192.0.2.10", Direction: "receives", DecoderFamily: "udp", StartedAt: time.Now()})
	dao13dCheck(f.t, err)
	if ended {
		f.exec("UPDATE attacks SET ended_at=now() WHERE id=$1", id)
	}
	return id
}
func (f *dao13dFixture) log(attack int, kind, rule, phase string) {
	f.t.Helper()
	_, err := f.db.ActionExecLog().Create(f.c, &store.ActionExecutionLog{AttackID: attack, ActionID: 10, ConnectorID: &f.cid, ActionType: kind, ExternalRuleID: rule, TriggerPhase: phase, Status: "success"})
	dao13dCheck(f.t, err)
}
func (f *dao13dFixture) attach(attack int, prefix string) store.BGPAttachResult {
	f.t.Helper()
	a, err := f.db.BGPAnnouncements().Attach(f.c, store.BGPAttachParams{AttackID: attack, ConnectorID: f.cid, Prefix: prefix, RouteMap: "RTBH"})
	dao13dCheck(f.t, err)
	return a
}
func (f *dao13dFixture) row(prefix string) *store.BGPAnnouncement {
	f.t.Helper()
	a, err := f.db.BGPAnnouncements().FindByBusinessKey(f.c, prefix, "RTBH", f.cid)
	dao13dCheck(f.t, err)
	return a
}
func (f *dao13dFixture) history() bool {
	f.t.Helper()
	b, err := f.db.BGPAnnouncements().HasOperationalHistory(f.c)
	dao13dCheck(f.t, err)
	return b
}
func (f *dao13dFixture) network(prefix string) int {
	f.t.Helper()
	b, err := os.ReadFile(f.record)
	if os.IsNotExist(err) {
		return 0
	}
	dao13dCheck(f.t, err)
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "network "+prefix+" ") {
			n++
		}
	}
	return n
}
func (f *dao13dFixture) script(prefix string, present, failRetry bool) {
	f.t.Helper()
	quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
	config, rib, j := "", "", "{}"
	if present {
		config = "router bgp 64512\n address-family ipv4 unicast\n  network " + prefix + " route-map RTBH\n exit-address-family\n"
		rib = "*> " + prefix + " 0.0.0.0 0 32768 i\n"
		j = fmt.Sprintf("{\"routes\":{%q:[{\"valid\":true,\"weight\":32768,\"peerId\":\"(unspec)\",\"path\":\"\",\"nexthops\":[{\"ip\":\"0.0.0.0\"}]}]}}", prefix)
	}
	body := "#!/bin/sh\nfor arg do printf '%s\\n' \"$arg\" >> " + quote(f.record) + "; done\ncase \"$*\" in\n" +
		" *'show running-config'*) printf '%s' " + quote(config) + ";;\n" +
		" *'show bgp ipv4 unicast json'*) printf '%s' " + quote(j) + ";;\n" +
		" *'show bgp ipv4 unicast'*) printf '%s' " + quote(rib) + ";;\n"
	if failRetry {
		body += " *'network " + prefix + " route-map RTBH'*) if [ -f " + quote(f.record+".sent") + " ]; then exit 1; fi; : > " + quote(f.record+".sent") + ";;\n"
	}
	body += "esac\n"
	dao13dCheck(f.t, os.WriteFile(f.path, []byte(body), 0700))
}
func dao13dChain(t *testing.T, bug bool) {
	f := dao13dNew(t)
	p := "192.0.2.10/32"
	r := f.db.BGPAnnouncements()
	a1 := f.attack(true)
	f.log(a1, "bgp", p+"|RTBH", "on_detected")
	a := f.attach(a1, p)
	dao13dCheck(t, r.MarkAnnounced(f.c, a.AnnouncementID, a.Gen))
	_, gen, err := r.ForceWithdraw(f.c, a.AnnouncementID)
	dao13dCheck(t, err)
	dao13dCheck(t, r.MarkWithdrawn(f.c, a.AnnouncementID, gen))
	a3 := f.attack(false)
	a = f.attach(a3, p)
	dao13dWant(t, "P10-A2.Recycled", a.Gen > 0)
	before, err := r.ListEvents(f.c, a.AnnouncementID)
	dao13dCheck(t, err)
	dao13dCheck(t, r.MarkFailedAnnounce(f.c, a.AnnouncementID, a.Gen, "definite failure"))
	if bug {
		dao13dWant(t, "R0.a.Deleted", f.row(p) == nil)
	} else {
		row := f.row(p)
		dao13dWant(t, "P10-A2.FailedRetained", row != nil && row.Status == "failed" && row.Gen == a.Gen)
		dao13dWant(t, "P10-A2.AttachmentRetained", f.count("SELECT count(*) FROM bgp_announcement_attacks WHERE announcement_id=$1 AND attack_id=$2 AND detached_at IS NULL", a.AnnouncementID, a3) == 1)
		dao13dWant(t, "P10-A2.FailureEvent", f.count("SELECT count(*) FROM bgp_announcement_events WHERE announcement_id=$1", a.AnnouncementID) == len(before)+1 && f.count("SELECT count(*) FROM bgp_announcement_events WHERE announcement_id=$1 AND event_type='announce_failed'", a.AnnouncementID) == 1)
	}
	f.migrate(dao13dRetention())
	row := f.row(p)
	if bug {
		dao13dWant(t, "R0.a.ResurrectedActive", row != nil && row.Status == "active" && row.Refcount == 1)
		dao13dWant(t, "R0.a.OldAttackAttached", f.count("SELECT count(*) FROM bgp_announcement_attacks WHERE announcement_id=$1 AND attack_id=$2", row.ID, a1) == 1)
	} else {
		dao13dWant(t, "P10-A2.StillFailed", row != nil && row.Status == "failed")
		dao13dWant(t, "P10-A2.OldAttackNotAttached", f.count("SELECT count(*) FROM bgp_announcement_attacks WHERE announcement_id=$1 AND attack_id=$2 AND detached_at IS NULL", row.ID, a1) == 0)
		active, err := r.ListActive(f.c)
		dao13dCheck(t, err)
		dao13dWant(t, "P10-A2.HistoryVisible", f.history() && len(active) == 1 && active[0].ID == row.ID)
	}
	action.RecoverBGPRoutes(f.c, f.db)
	want := 0
	if bug {
		want = 1
	}
	dao13dWant(t, "R0.a.RecoveryNetwork", f.network(p) == want)
}
func dao13dAttachment(t *testing.T, bug bool) {
	f := dao13dNew(t)
	p := "198.51.100.0/24"
	c := f.attack(false)
	a := f.attach(c, p)
	dao13dCheck(t, f.db.BGPAnnouncements().MarkAnnounced(f.c, a.AnnouncementID, a.Gen))
	b := f.attack(true)
	f.log(b, "bgp", p+"|RTBH", "on_detected")
	f.migrate(dao13dRetention())
	got := f.count("SELECT count(*) FROM bgp_announcement_attacks WHERE announcement_id=$1 AND attack_id=$2", a.AnnouncementID, b)
	want := 0
	if bug {
		want = 1
	}
	dao13dWant(t, "P10-C.HistoricalAttachment", got == want)
	dao13dWant(t, "P10-C.CurrentUnchanged", f.row(p).Refcount == 1 && f.count("SELECT count(*) FROM bgp_announcement_attacks WHERE announcement_id=$1 AND attack_id=$2 AND detached_at IS NULL", a.AnnouncementID, c) == 1)
}
func dao13dHistory(t *testing.T, other, bug bool) {
	f := dao13dNew(t)
	p := "192.0.2.20/32"
	r := f.db.BGPAnnouncements()
	if other {
		a := f.attach(f.attack(true), "198.51.100.20/32")
		_, g, e := r.ForceWithdraw(f.c, a.AnnouncementID)
		dao13dCheck(t, e)
		dao13dCheck(t, r.MarkWithdrawn(f.c, a.AnnouncementID, g))
	}
	a := f.attach(f.attack(true), p)
	dao13dCheck(t, r.MarkAnnounced(f.c, a.AnnouncementID, a.Gen))
	_, gen, err := r.ForceWithdraw(f.c, a.AnnouncementID)
	dao13dCheck(t, err)
	dao13dCheck(t, r.MarkFailedWithdraw(f.c, a.AnnouncementID, gen, "withdraw failed"))
	a = f.attach(f.attack(false), p)
	dao13dCheck(t, r.MarkFailedAnnounce(f.c, a.AnnouncementID, a.Gen, "announce failed"))
	dao13dWant(t, "P10-E.HistoryBeforeBootstrap", f.history() == (!bug || other))
	if bug {
		dao13dWant(t, "R0.h.LastRowDeleted", f.row(p) == nil)
	} else {
		dao13dWant(t, "P10-E.FailedRetained", f.row(p) != nil && f.row(p).Status == "failed")
	}
	f.script(p, true, false)
	action.BootstrapBGPOrphans(f.c, f.db)
	row := f.row(p)
	if bug {
		dao13dWant(t, "R0.h.SilentUpgrade", row != nil && row.Status == "dismissed_on_upgrade")
	} else {
		dao13dWant(t, "P10-E.NoSilentUpgrade", row != nil && row.Status == "failed" && f.count("SELECT count(*) FROM bgp_announcements WHERE status='dismissed_on_upgrade'") == 0)
		active, err := r.ListActive(f.c)
		dao13dCheck(t, err)
		found := false
		for _, v := range active {
			if v.ID == row.ID {
				found = true
			}
		}
		dao13dWant(t, "P10-E.ListActive", found)
	}
}

type dao13dLogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *dao13dLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *dao13dLogBuffer) text() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
func dao13dUntil(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-deadline.C:
			t.Fatal("required observation missing after 10s")
		case <-tick.C:
		}
	}
}
func dao13dStartup(t *testing.T, absent, bug, headControl bool) {
	f := dao13dNew(t)
	p := "192.0.2.30/32"
	r := f.db.BGPAnnouncements()
	f.script(p, true, true)
	attack := f.attack(false)
	a := f.attach(attack, p)
	// State-equivalent construction: the first network succeeds, MarkAnnounced is deliberately omitted.
	c, cancel := context.WithTimeout(f.c, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, f.path, "-c", "configure terminal\nrouter bgp 64512\naddress-family ipv4 unicast\nnetwork "+p+" route-map RTBH").CombinedOutput()
	dao13dCheck(t, err)
	t.Logf("State-equivalent construction, first announce output=%s", out)
	f.log(attack, "bgp", p+"|RTBH", "on_detected")
	f.exec("UPDATE attacks SET ended_at=now() WHERE id=$1", attack)
	before := f.row(p)
	events := f.count("SELECT count(*) FROM bgp_announcement_events WHERE announcement_id=$1", a.AnnouncementID)
	dao13dWant(t, "G0.Fixture", before != nil && before.Gen == 0 && before.Status == "announcing" && before.Refcount == 1 && f.network(p) == 1)
	var logs dao13dLogBuffer
	prior := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prior)
	engine := action.NewEngine(f.db, "auto")
	engine.ReconcileOnStartup(f.c)
	if bug {
		dao13dUntil(t, func() bool { return f.row(p) == nil })
		dao13dWant(t, "R0.i.LastHistoryLost", !f.history())
	} else {
		dao13dUntil(t, func() bool { return strings.Contains(logs.text(), "WARN action: retry announce") })
		dao13dWant(t, "P10-G0.Retained", reflect.DeepEqual(before, f.row(p)) && f.history())
		dao13dWant(t, "P10-G0.AttachmentsEvents", f.count("SELECT count(*) FROM bgp_announcement_attacks WHERE announcement_id=$1 AND attack_id=$2 AND detached_at IS NULL", a.AnnouncementID, attack) == 1 && f.count("SELECT count(*) FROM bgp_announcement_events WHERE announcement_id=$1", a.AnnouncementID) >= events)
	}
	dao13dWant(t, "G0.TwoNetworkAttempts", f.network(p) == 2)
	if bug && headControl {
		f.migrate(dao13dRetention())
		row := f.row(p)
		dao13dWant(t, "R0.i-1.BackfillSelfHeal", row != nil && row.Status == "active" && f.count("SELECT count(*) FROM bgp_announcement_attacks WHERE announcement_id=$1 AND attack_id=$2", row.ID, attack) == 1)
		return
	}
	action.BootstrapBGPOrphans(f.c, f.db)
	if bug {
		dao13dWant(t, "R0.i-2.SilentUpgrade", f.row(p) != nil && f.row(p).Status == "dismissed_on_upgrade")
		return
	}
	dao13dWant(t, "P10-G0.BootstrapKeepsRow", reflect.DeepEqual(before, f.row(p)) && f.count("SELECT count(*) FROM bgp_announcements WHERE status='dismissed_on_upgrade'") == 0)
	f.migrate(dao13dRetention())
	dao13dWant(t, "P10-G0.MigrationKeepsRow", reflect.DeepEqual(before, f.row(p)))
	f.script(p, !absent, true)
	var metric dto.Metric
	dao13dCheck(t, metrics.BGPAnnouncingReconcile.WithLabelValues("absent").Write(&metric))
	absentBefore := metric.GetCounter().GetValue()
	loop, stop := context.WithCancel(f.c)
	done := make(chan struct{})
	go func() { defer close(done); engine.RunAnnouncingReconcile(loop, 20*time.Millisecond) }()
	defer func() {
		stop()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("reconcile did not join")
		}
	}()
	dao13dUntil(t, func() bool {
		if absent {
			dao13dCheck(t, metrics.BGPAnnouncingReconcile.WithLabelValues("absent").Write(&metric))
			return metric.GetCounter().GetValue()-absentBefore >= 1
		}
		return f.row(p).Status == "active"
	})
	stop()
	<-done
	row, err := r.Get(f.c, a.AnnouncementID)
	dao13dCheck(t, err)
	want := "active"
	if absent {
		want = "announcing"
	}
	dao13dWant(t, "P10-G0.RuntimeReadOnly", row != nil && row.Status == want && row.ID == a.AnnouncementID && f.network(p) == 2 && f.count("SELECT count(*) FROM bgp_announcements") == 1 && f.count("SELECT count(*) FROM bgp_announcements WHERE status='dismissed_on_upgrade'") == 0)
	t.Logf("RAW startup logs: %s", logs.text())
}

func dao13dOldSeed(f *dao13dFixture) []int {
	dao13dOldBGP(f.t, f.db)
	ids := []int{f.attack(false), f.attack(false), f.attack(true)}
	for _, id := range ids[:2] {
		f.log(id, "bgp", "192.0.2.40/32|RTBH", "on_detected")
	}
	f.log(ids[2], "bgp", "192.0.2.41/32|RTBH", "on_detected")
	f.log(ids[2], "bgp", "192.0.2.41/32|RTBH", "on_expired")
	return ids
}
func dao13dOldResult(f *dao13dFixture, ids []int) {
	f.t.Helper()
	row := f.row("192.0.2.40/32")
	dao13dWant(f.t, "P10-B.ExpectedAnnouncement", row != nil && row.Status == "active" && row.Refcount == 2 && f.row("192.0.2.41/32") == nil && f.count("SELECT count(*) FROM bgp_announcements") == 1)
	rows, err := f.db.BGPAnnouncements().ListAttacks(f.c, row.ID)
	dao13dCheck(f.t, err)
	got := []int{}
	for _, r := range rows {
		got = append(got, r.AttackID)
	}
	sort.Ints(got)
	dao13dWant(f.t, "P10-B.ExpectedAttachments", reflect.DeepEqual(got, ids[:2]))
	f.t.Logf("Canonical backfill result: prefix=%s status=%s refcount=%d attachments=%v excluded=%d", row.Prefix, row.Status, row.Refcount, got, ids[2])
}
func dao13dReentry(t *testing.T, where string) {
	control := dao13dNew(t)
	controlIDs := dao13dOldSeed(control)
	control.migrate(dao13dRetention())
	dao13dOldResult(control, controlIDs)
	f := dao13dNew(t)
	ids := dao13dOldSeed(f)
	if where == "P10-R1" {
		f.exec("CREATE VIEW bgp_announcement_events AS SELECT 1 AS announcement_id")
	} else {
		ddl := ""
		for _, s := range migrations {
			if strings.HasPrefix(s, "CREATE TABLE IF NOT EXISTS bgp_announcement_attacks") {
				ddl = s
			}
		}
		dao13dWant(t, "R2.FixtureDDL", ddl != "")
		ddl = strings.ReplaceAll(ddl, " REFERENCES bgp_announcements(id) ON DELETE CASCADE", "")
		ddl = strings.Replace(ddl, "PRIMARY KEY (announcement_id, attack_id)", "PRIMARY KEY (announcement_id, attack_id), CHECK (attack_id < 0)", 1)
		f.exec(ddl)
	}
	err := f.db.AutoMigrate(f.c, dao13dRetention())
	t.Logf("RAW injected migration error: %v", err)
	dao13dWant(t, where+".Failed", err != nil)
	var absent bool
	dao13dCheck(t, f.db.pool.QueryRow(f.c, "SELECT to_regclass('bgp_announcements') IS NULL").Scan(&absent))
	dao13dWant(t, where+".Rollback", absent)
	if where == "P10-R1" {
		f.exec("DROP VIEW bgp_announcement_events")
	} else {
		f.exec("DROP TABLE bgp_announcement_attacks")
	}
	f.migrate(dao13dRetention())
	dao13dOldResult(f, ids)
	if where == "P10-R2" {
		r, err := f.db.BGPAnnouncements().ReconcileAttachments(f.c, f.row("192.0.2.40/32").ID, nil, true)
		dao13dCheck(t, err)
		dao13dWant(t, "P10-R2.RefcountConsistent", r.Skipped != "refcount_exceeds_attachments")
	}
}
func (f *dao13dFixture) oldWebhooks() {
	f.exec("DROP TABLE webhook_connectors CASCADE")
	f.t.Log("Old-schema simulation drops response_actions.webhook_connector_id foreign key; it is not restored. This is not a complete historical schema upgrade.")
}
func (f *dao13dFixture) webhook(headers any, enabled bool) int {
	var id int
	dao13dCheck(f.t, f.db.pool.QueryRow(f.c, "INSERT INTO webhooks(url,headers,enabled) VALUES('https://hooks.example/a',$1::jsonb,$2) RETURNING id", headers, enabled).Scan(&id))
	return id
}
func dao13dWebhookBug(t *testing.T) {
	f := dao13dNew(t)
	id := f.webhook("{\"Authorization\":\"Bearer t0ken\"}", true)
	f.migrate(dao13dRetention())
	var cid int
	var headers string
	dao13dCheck(t, f.db.pool.QueryRow(f.c, "SELECT id,headers::text FROM webhook_connectors WHERE name=$1", fmt.Sprintf("legacy-webhook-%d", id)).Scan(&cid, &headers))
	dao13dWant(t, "R0.c.HeadersLost", headers == "{}")
	dao13dCheck(t, f.db.WebhookConnectors().Delete(f.c, cid))
	f.migrate(dao13dRetention())
	dao13dWant(t, "R0.c.Resurrected", f.count("SELECT count(*) FROM webhook_connectors WHERE name=$1", fmt.Sprintf("legacy-webhook-%d", id)) == 1)
}

type dao13dJob struct {
	ID     int
	Config string
}

func (f *dao13dFixture) jobs(table, proc string) []dao13dJob {
	f.t.Helper()
	query := "SELECT job_id,config::text,to_jsonb(j)::text FROM timescaledb_information.jobs j WHERE proc_name=$2 AND (hypertable_name=$1 OR (hypertable_schema,hypertable_name) IN (SELECT materialization_hypertable_schema,materialization_hypertable_name FROM timescaledb_information.continuous_aggregates WHERE view_schema=current_schema() AND view_name=$1)) ORDER BY job_id"
	rows, err := f.db.pool.Query(f.c, query, table, proc)
	dao13dCheck(f.t, err)
	defer rows.Close()
	result := []dao13dJob{}
	for rows.Next() {
		var j dao13dJob
		var raw string
		dao13dCheck(f.t, rows.Scan(&j.ID, &j.Config, &raw))
		f.t.Logf("RAW jobs table=%s proc=%s %s", table, proc, raw)
		result = append(result, j)
	}
	dao13dCheck(f.t, rows.Err())
	return result
}
func dao13dPolicies(t *testing.T, bug bool) {
	f := dao13dNew(t)
	ret := dao13dRetention()
	f.migrate(ret)
	for _, table := range []string{"ts_stats", "flow_logs"} {
		for _, kind := range []string{"policy_retention", "policy_compression"} {
			dao13dWant(t, "P11.Fixture."+table+"."+kind, len(f.jobs(table, kind)) == 1)
		}
	}
	ret.TSStatsDays, ret.FlowLogsDays, ret.TSStatsCompressDays, ret.FlowLogsCompressDays = 0, 0, 0, 0
	f.migrate(ret)
	n := 0
	if bug {
		n = 1
	}
	for _, table := range []string{"ts_stats", "flow_logs"} {
		for _, kind := range []string{"policy_retention", "policy_compression"} {
			dao13dWant(t, "P11-A.Zero."+table+"."+kind, len(f.jobs(table, kind)) == n)
		}
	}
	if bug {
		return
	}
	f.migrate(ret)
	for _, table := range []string{"ts_stats", "flow_logs"} {
		dao13dWant(t, "P11-A.ZeroAgain."+table, len(f.jobs(table, "policy_retention")) == 0)
	}
	ret.TSStatsDays, ret.FlowLogsDays = 7, 7
	f.migrate(ret)
	for _, table := range []string{"ts_stats", "flow_logs"} {
		jobs := f.jobs(table, "policy_retention")
		dao13dWant(t, "P11-A.Restored."+table, len(jobs) == 1)
		dao13dWant(t, "P11-A.SevenDays."+table, f.count("SELECT count(*) FROM timescaledb_information.jobs WHERE job_id=$1 AND (config->>'drop_after')::interval=interval '7 days'", jobs[0].ID) == 1)
	}
}
func TestDao13d_R0Fixed(t *testing.T) {
	cases := []struct {
		name string
		run  func(*testing.T)
	}{
		{"P10-A", func(t *testing.T) {
			f := dao13dNew(t)
			p := "192.0.2.10/32"
			a1 := f.attack(true)
			f.log(a1, "bgp", p+"|RTBH", "on_detected")
			a := f.attach(f.attack(false), p)
			dao13dWant(t, "P10-A.FixtureGen0", a.Gen == 0)
			dao13dCheck(t, f.db.BGPAnnouncements().MarkFailedAnnounce(f.c, a.AnnouncementID, a.Gen, "failure"))
			dao13dWant(t, "P10-A.Gen0Deleted", f.row(p) == nil)
			f.migrate(dao13dRetention())
			dao13dWant(t, "P10-A.NoResurrection", f.row(p) == nil)
			action.RecoverBGPRoutes(f.c, f.db)
			dao13dWant(t, "P10-A.NoNetworkOldLogKept", f.network(p) == 0 && f.count("SELECT count(*) FROM action_execution_log WHERE attack_id=$1", a1) == 1)
		}},
		{"P10-A2", func(t *testing.T) { dao13dChain(t, false) }},
		{"P10-B", func(t *testing.T) {
			f := dao13dNew(t)
			ids := dao13dOldSeed(f)
			f.migrate(dao13dRetention())
			dao13dOldResult(f, ids)
			f.exec("DELETE FROM bgp_announcements")
			f.migrate(dao13dRetention())
			dao13dWant(t, "P10-B.SecondMigrationNoRows", f.count("SELECT count(*) FROM bgp_announcements") == 0)
			f.migrate(dao13dRetention())
		}},
		{"P10-C", func(t *testing.T) { dao13dAttachment(t, false) }},
		{"P10-D", func(t *testing.T) {
			f := dao13dNew(t)
			a := f.attack(false)
			f.log(a, "xdrop", "dao13d-rule", "on_detected")
			f.log(a, "manual_override", "different-rule", "manual_override")
			f.migrate(dao13dRetention())
			dao13dWant(t, "P10-D.XDropFallback", f.count("SELECT count(*) FROM xdrop_active_rules WHERE attack_id=$1 AND external_rule_id='dao13d-rule'", a) == 1)
			dao13dWant(t, "P10-D.OverrideFallback", f.count("SELECT count(*) FROM action_manual_overrides WHERE attack_id=$1 AND external_rule_id='different-rule'", a) == 1)
		}},
		{"P10-R1", func(t *testing.T) { dao13dReentry(t, "P10-R1") }},
		{"P10-R2", func(t *testing.T) { dao13dReentry(t, "P10-R2") }},
		{"P10-R3", func(t *testing.T) {
			f := dao13dNew(t)
			f.oldWebhooks()
			id := f.webhook("{\"Authorization\":\"Bearer t0ken\"}", true)
			f.exec("ALTER TABLE webhooks ALTER COLUMN headers TYPE text")
			err := f.db.AutoMigrate(f.c, dao13dRetention())
			t.Logf("RAW injected migration error: %v", err)
			dao13dWant(t, "P10-R3.CopyFailed", err != nil)
			var absent bool
			dao13dCheck(t, f.db.pool.QueryRow(f.c, "SELECT to_regclass('webhook_connectors') IS NULL").Scan(&absent))
			dao13dWant(t, "P10-R3.Rollback", absent)
			f.exec("ALTER TABLE webhooks ALTER COLUMN headers DROP DEFAULT")
			f.exec("ALTER TABLE webhooks ALTER COLUMN headers TYPE jsonb USING headers::jsonb")
			f.migrate(dao13dRetention())
			dao13dWant(t, "P10-R3.Reentered", f.count("SELECT count(*) FROM webhook_connectors c JOIN webhooks w ON c.name='legacy-webhook-'||w.id WHERE w.id=$1 AND c.headers=w.headers", id) == 1)
		}},
		{"P10-E1", func(t *testing.T) { dao13dHistory(t, true, false) }},
		{"P10-E2", func(t *testing.T) { dao13dHistory(t, false, false) }},
		{"P10-G0", func(t *testing.T) {
			t.Run("Present", func(t *testing.T) { dao13dStartup(t, false, false, false) })
			t.Run("RouteAbsent", func(t *testing.T) { dao13dStartup(t, true, false, false) })
		}},
		{"D6-A", func(t *testing.T) {
			t.Run("Existing", func(t *testing.T) {
				f := dao13dNew(t)
				f.webhook("{\"Authorization\":\"Bearer t0ken\"}", true)
				f.migrate(dao13dRetention())
				dao13dWant(t, "D6-A.ExistingNotCopied", f.count("SELECT count(*) FROM webhook_connectors") == 0)
			})
			t.Run("Old", func(t *testing.T) {
				f := dao13dNew(t)
				f.oldWebhooks()
				a := f.webhook("{\"Authorization\":\"Bearer t0ken\"}", true)
				b := f.webhook("{}", false)
				f.migrate(dao13dRetention())
				dao13dWant(t, "D6-A.HeadersEnabledGlobal", f.count("SELECT count(*) FROM webhook_connectors c JOIN webhooks w ON c.name='legacy-webhook-'||w.id WHERE c.headers=w.headers AND c.enabled=w.enabled AND c.global AND w.id IN ($1,$2)", a, b) == 2 && f.count("SELECT count(*) FROM webhook_connectors") == 2)
				f.exec("DELETE FROM webhook_connectors WHERE name=$1", fmt.Sprintf("legacy-webhook-%d", a))
				f.exec("UPDATE webhook_connectors SET name='renamed' WHERE name=$1", fmt.Sprintf("legacy-webhook-%d", b))
				f.migrate(dao13dRetention())
				dao13dWant(t, "D6-A.NoRevival", f.count("SELECT count(*) FROM webhook_connectors") == 1 && f.count("SELECT count(*) FROM webhook_connectors WHERE name LIKE 'legacy-webhook-%'") == 0)
			})
		}},
		{"D6-B", func(t *testing.T) {
			f := dao13dNew(t)
			f.oldWebhooks()
			f.webhook("\"Bearer t0ken\"", true)
			f.webhook(nil, true)
			f.migrate(dao13dRetention())
			dao13dWant(t, "D6-B.DirtyHeaders", f.count("SELECT count(*) FROM webhook_connectors WHERE headers='{}'::jsonb") == 2)
		}},
		{"P11-A", func(t *testing.T) { dao13dPolicies(t, false) }},
		{"P11-B", func(t *testing.T) {
			f := dao13dNew(t)
			ret := dao13dRetention()
			before := map[string][]dao13dJob{}
			for _, table := range []string{"ts_stats", "flow_logs"} {
				before[table] = f.jobs(table, "policy_compression")
				dao13dWant(t, "P11-B.CompressionFixture", len(before[table]) == 1)
			}
			ret.TSStatsDays, ret.FlowLogsDays = 0, 0
			f.migrate(ret)
			for _, table := range []string{"ts_stats", "flow_logs"} {
				dao13dWant(t, "P11-B.CompressionIndependent."+table, reflect.DeepEqual(before[table], f.jobs(table, "policy_compression")) && len(f.jobs(table, "policy_retention")) == 0)
			}
			ret.TSStatsDays, ret.FlowLogsDays = 7, 7
			f.migrate(ret)
			for _, table := range []string{"ts_stats", "flow_logs"} {
				before[table] = f.jobs(table, "policy_retention")
				dao13dWant(t, "P11-B.RetentionFixture", len(before[table]) == 1)
			}
			ret.TSStatsCompressDays, ret.FlowLogsCompressDays = 0, 0
			f.migrate(ret)
			for _, table := range []string{"ts_stats", "flow_logs"} {
				dao13dWant(t, "P11-B.RetentionIndependent."+table, reflect.DeepEqual(before[table], f.jobs(table, "policy_retention")) && len(f.jobs(table, "policy_compression")) == 0)
			}
		}},
		{"P11-C", func(t *testing.T) {
			f := dao13dNew(t)
			ret := dao13dRetention()
			dao13dWant(t, "P11-C.Positive90", len(f.jobs("ts_stats_5min", "policy_retention")) == 1)
			ret.TSStatsCaggDays = 0
			f.migrate(ret)
			dao13dWant(t, "P11-C.Zero", len(f.jobs("ts_stats_5min", "policy_retention")) == 0)
			ret.TSStatsCaggDays = 90
			f.migrate(ret)
			jobs := f.jobs("ts_stats_5min", "policy_retention")
			dao13dWant(t, "P11-C.Restored90", len(jobs) == 1 && f.count("SELECT count(*) FROM timescaledb_information.jobs WHERE job_id=$1 AND (config->>'drop_after')::interval=interval '90 days'", jobs[0].ID) == 1)
		}},
		{"B2-A", func(t *testing.T) {
			f := dao13dNew(t)
			before := map[string][]dao13dJob{}
			for _, table := range []string{"ts_stats", "flow_logs"} {
				for _, kind := range []string{"policy_retention", "policy_compression"} {
					before[table+kind] = f.jobs(table, kind)
					dao13dWant(t, "B2-A.RawFixture", len(before[table+kind]) == 1)
				}
			}
			f.migrate(dao13dRetention())
			for _, table := range []string{"ts_stats", "flow_logs"} {
				for _, kind := range []string{"policy_retention", "policy_compression"} {
					dao13dWant(t, "B2-A.RawUnchanged."+table+"."+kind, reflect.DeepEqual(before[table+kind], f.jobs(table, kind)))
				}
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func TestDao13d_B1_C(t *testing.T) {
	var s PGStore
	if s.IsHypertable("ts_stats") || s.IsHypertable("flow_logs") {
		t.Fatal("B1-C zero store must report ordinary tables")
	}
}
