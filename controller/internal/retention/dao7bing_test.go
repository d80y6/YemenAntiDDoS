package retention

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/d80y6/YemenDDoS/controller/internal/store/postgres"
)

// Each case owns a disposable database. This follows newPostgresContractBackend
// without depending on another package's unexported test helpers.
type dao7DB struct {
	t   *testing.T
	db  *postgres.PGStore
	ctx context.Context
	now time.Time
	old time.Time
}

func newDao7DB(t *testing.T) *dao7DB {
	t.Helper()
	dsn := os.Getenv("XSIGHT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("XSIGHT_TEST_ADMIN_DSN is not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	t.Cleanup(func() {
		if err := admin.Close(context.Background()); err != nil {
			t.Errorf("close admin: %v", err)
		}
	})
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	name := "xsight_ct_" + hex.EncodeToString(random[:])
	if !regexp.MustCompile(`^xsight_ct_[0-9a-f]{16}$`).MatchString(name) {
		t.Fatalf("unsafe database name %q", name)
	}
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatalf("create contract database: %v", err)
	}
	var db *postgres.PGStore
	// Register immediately: failed construction or migration also drops the DB.
	t.Cleanup(func() {
		if db != nil {
			db.Close()
		}
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
	})
	targetDSN := dsn + " dbname=" + name
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		u.Path = "/" + name
		q := u.Query()
		q.Set("dbname", name)
		u.RawQuery = q.Encode()
		targetDSN = u.String()
	}
	db, err = postgres.New(ctx, targetDSN)
	if err != nil {
		t.Fatalf("open contract database: %v", err)
	}
	var actual string
	if err := db.Pool().QueryRow(ctx, "SELECT current_database()").Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != name {
		t.Fatalf("refusing migration: current_database=%q, want %q", actual, name)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := &dao7DB{t: t, db: db, ctx: ctx, now: now, old: now.Add(-90 * 24 * time.Hour)}
	d.migrate()
	var count int
	if err := db.Pool().QueryRow(ctx, `SELECT count(DISTINCT hypertable_name) FROM timescaledb_information.hypertables WHERE hypertable_schema='public' AND hypertable_name IN ('ts_stats','flow_logs')`).Scan(&count); err != nil {
		t.Fatalf("verify hypertables: %v", err)
	}
	if count != 2 {
		t.Fatalf("required hypertables found=%d; want ts_stats and flow_logs", count)
	}
	return d
}

func (d *dao7DB) migrate() {
	d.t.Helper()
	if err := d.db.AutoMigrate(d.ctx, postgres.RetentionConfig{TSStatsDays: 7, TSStatsCompressDays: 1, TSStatsCaggDays: 90, FlowLogsDays: 7, FlowLogsCompressDays: 1}); err != nil {
		d.t.Fatal(err)
	}
}

func (d *dao7DB) exec(q string, args ...any) {
	d.t.Helper()
	if _, err := d.db.Pool().Exec(d.ctx, q, args...); err != nil {
		d.t.Fatalf("fixture SQL %s: %v", q, err)
	}
}

func (d *dao7DB) id(q string, args ...any) int {
	d.t.Helper()
	var id int
	if err := d.db.Pool().QueryRow(d.ctx, q, args...).Scan(&id); err != nil {
		d.t.Fatalf("fixture SQL %s: %v", q, err)
	}
	return id
}

func (d *dao7DB) attack(ended any) int {
	return d.id(`INSERT INTO attacks (dst_ip, decoder_family, started_at, ended_at) VALUES ('192.0.2.1','tcp', $1, $2) RETURNING id`, d.old.Add(-24*time.Hour), ended)
}

func (d *dao7DB) log(attack, action, connector int, kind, phase, rule string) {
	d.exec(`INSERT INTO action_execution_log (attack_id, action_id, connector_id, action_type, trigger_phase, status, external_rule_id, executed_at) VALUES ($1,$2,$3,$4,$5,'success',$6,$7)`, attack, action, connector, kind, phase, rule, d.old)
}

func (d *dao7DB) rule(attack, action int, status string) {
	d.exec(`INSERT INTO xdrop_active_rules (attack_id, action_id, connector_id, external_rule_id, status, created_at) VALUES ($1,$2,7,'rule-1',$3,$4)`, attack, action, status, d.old)
}

func (d *dao7DB) announcement(status string) int {
	return d.id(`INSERT INTO bgp_announcements (prefix, route_map, connector_id, status, announced_at) VALUES ('198.51.100.0/24','RM',8,$1,$2) RETURNING id`, status, d.old)
}

func (d *dao7DB) attach(attack, announcement int, detached any) {
	d.exec(`INSERT INTO bgp_announcement_attacks (attack_id, announcement_id, action_id, attached_at, detached_at) VALUES ($1,$2,201,$3,$4)`, attack, announcement, d.old, detached)
}

func (d *dao7DB) event(announcement int, attack any, created time.Time) int {
	return d.id(`INSERT INTO bgp_announcement_events (announcement_id, attack_id, event_type, created_at) VALUES ($1,$2,'attach',$3) RETURNING id`, announcement, attack, created)
}

func (d *dao7DB) schedule(attack int, status string) {
	d.exec(`INSERT INTO scheduled_actions (action_type, attack_id, action_id, connector_id, external_rule_id, scheduled_for, status) VALUES ('xdrop_unblock',$1,101,7,'rule-1',$2,$3)`, attack, d.old, status)
}

func (d *dao7DB) legacyLog(attack int) {
	d.exec(`INSERT INTO actions_log (attack_id, execution_policy, status, first_attempt_at, last_attempt_at) VALUES ($1,'once','success',$2,$2)`, attack, d.old)
}

var dao7Tables = []string{"attacks", "action_execution_log", "xdrop_active_rules", "scheduled_actions", "bgp_announcement_attacks", "bgp_announcement_events", "action_manual_overrides", "actions_log"}

// Full row sets also catch an accidental update that leaves counts unchanged.
func (d *dao7DB) snapshot(label string, attacks ...int) map[string][]string {
	d.t.Helper()
	sets := make(map[string][]string)
	for _, table := range dao7Tables {
		key := "attack_id"
		if table == "attacks" {
			key = "id"
		}
		rows, err := d.db.Pool().Query(d.ctx, "SELECT to_jsonb(t)::text FROM "+pgx.Identifier{table}.Sanitize()+" t WHERE "+key+" = ANY($1) ORDER BY to_jsonb(t)::text", attacks)
		if err != nil {
			d.t.Fatal(err)
		}
		set, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			d.t.Fatal(err)
		}
		sets[table] = set
		d.t.Logf("%s %s attack_id∈%v count=%d rows=%v", label, table, attacks, len(set), set)
	}
	return sets
}

func (d *dao7DB) counts(sets map[string][]string, want map[string]int) {
	d.t.Helper()
	for _, table := range dao7Tables {
		if got := len(sets[table]); got != want[table] {
			d.t.Errorf("%s count=%d, want %d; rows=%v", table, got, want[table], sets[table])
		}
	}
}

func (d *dao7DB) unchanged(before, after map[string][]string) {
	d.t.Helper()
	for _, table := range dao7Tables {
		if !reflect.DeepEqual(before[table], after[table]) {
			d.t.Errorf("%s changed: before=%v after=%v", table, before[table], after[table])
		}
	}
}

func (d *dao7DB) clean(want int64) {
	d.t.Helper()
	n, err := New(d.db.Pool(), Config{AttacksDays: 30}).deleteOldAttacks(d.ctx, 30)
	if err != nil {
		d.t.Fatalf("Cleaner: %v", err)
	}
	if n != want {
		d.t.Errorf("deleted attack count=%d, want %d", n, want)
	}
}

// R1 uses four execution logs. Paired withdrawals use
// different action IDs, but match the attack/connector/rule business key.
func (d *dao7DB) terminalAttack() int {
	a := d.attack(d.old)
	d.log(a, 101, 7, "xdrop", "on_detected", "rule-1")
	d.log(a, 102, 7, "xdrop", "on_expired", "rule-1")
	d.log(a, 201, 8, "bgp", "on_detected", "198.51.100.0/24|RM")
	d.log(a, 202, 8, "bgp", "on_expired", "198.51.100.0/24|RM")
	d.rule(a, 101, "withdrawn")
	d.schedule(a, "completed")
	// Reuse the terminal announcement for the R8 batch fixture.
	p := d.id(`INSERT INTO bgp_announcements (prefix, route_map, connector_id, status) VALUES ('198.51.100.0/24','RM',8,'withdrawn') ON CONFLICT (prefix, route_map, connector_id) DO UPDATE SET status=EXCLUDED.status RETURNING id`)
	d.attach(a, p, d.old)
	d.exec(`INSERT INTO action_manual_overrides (attack_id, action_id, connector_id, external_rule_id) VALUES ($1,101,7,'rule-1')`, a)
	d.event(p, a, d.old)
	d.legacyLog(a)
	d.counts(d.snapshot("terminal fixture", a), map[string]int{"attacks": 1, "action_execution_log": 4, "xdrop_active_rules": 1, "scheduled_actions": 1, "bgp_announcement_attacks": 1, "bgp_announcement_events": 1, "action_manual_overrides": 1, "actions_log": 1})
	return a
}

func TestDao7bing_R1_TerminalAttack(t *testing.T) {
	d := newDao7DB(t)
	a := d.terminalAttack()
	d.clean(1)
	d.counts(d.snapshot("after Cleaner", a), nil)
}

func TestDao7bing_R2_Unfinished(t *testing.T) {
	cases := []struct {
		name  string
		seed  func(*dao7DB, int)
		table string
	}{
		{"B1_active_rule", func(d *dao7DB, a int) { d.rule(a, 101, "active") }, "xdrop_active_rules"},
		{"B2_failed_rule", func(d *dao7DB, a int) { d.rule(a, 101, "failed") }, "xdrop_active_rules"},
		{"B3_attached_withdrawn", func(d *dao7DB, a int) { d.attach(a, d.announcement("withdrawn"), nil) }, "bgp_announcement_attacks"},
		{"B4_pending_schedule", func(d *dao7DB, a int) { d.schedule(a, "pending") }, "scheduled_actions"},
		{"B5_detached_failed", func(d *dao7DB, a int) { d.attach(a, d.announcement("failed"), d.old) }, "bgp_announcement_attacks"},
		{"B6_xdrop_log_only", func(d *dao7DB, a int) { d.log(a, 101, 7, "xdrop", "on_detected", "rule-1") }, "action_execution_log"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDao7DB(t)
			a := d.attack(d.old)
			tc.seed(d, a)
			// B1-B5 have a non-recoverable audit log and the legacy FK log;
			// neither introduces another unfinished-state guard. B6 is log-only.
			want := map[string]int{"attacks": 1, tc.table: 1}
			if tc.name != "B6_xdrop_log_only" {
				d.log(a, 301, 9, "webhook", "on_detected", "audit-only")
				d.legacyLog(a)
				want["action_execution_log"], want["actions_log"] = 1, 1
			}
			before := d.snapshot("before Cleaner", a)
			d.counts(before, want)
			d.clean(0)
			d.unchanged(before, d.snapshot("after Cleaner", a))
		})
	}
}

func TestDao7bing_R3_NoResurrection(t *testing.T) {
	d := newDao7DB(t)
	a := d.terminalAttack()
	d.clean(1)
	d.counts(d.snapshot("R1 deletion", a), nil)
	positive := d.attack(d.old)
	d.log(positive, 101, 7, "xdrop", "on_detected", "rule-1")
	d.rule(positive, 101, "active")
	d.exec(`DELETE FROM xdrop_active_rules WHERE attack_id=$1`, positive)
	d.counts(d.snapshot("positive control states removed", positive), map[string]int{"attacks": 1, "action_execution_log": 1})
	d.snapshot("before AutoMigrate A+A′", a, positive)
	d.migrate()
	d.snapshot("after AutoMigrate A+A′", a, positive)
	d.counts(d.snapshot("A remains absent", a), nil)
	d.counts(d.snapshot("A′ rule restored", positive), map[string]int{"attacks": 1, "action_execution_log": 1, "xdrop_active_rules": 1})
	var status string
	if err := d.db.Pool().QueryRow(d.ctx, `SELECT status FROM xdrop_active_rules WHERE attack_id=$1 AND action_id=101 AND connector_id=7 AND external_rule_id='rule-1'`, positive).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Errorf("positive rule status=%q, want active", status)
	}
}

func TestDao7bing_R4_TimeEligibility(t *testing.T) {
	for _, name := range []string{"C_live", "D_recently_ended"} {
		t.Run(name, func(t *testing.T) {
			d := newDao7DB(t)
			var ended any
			if name == "D_recently_ended" {
				ended = d.now.Add(-time.Hour)
			}
			a := d.attack(ended)
			d.log(a, 301, 9, "webhook", "on_detected", "audit-only")
			d.legacyLog(a)
			before := d.snapshot("before Cleaner", a)
			d.counts(before, map[string]int{"attacks": 1, "action_execution_log": 1, "actions_log": 1})
			d.clean(0)
			d.unchanged(before, d.snapshot("after Cleaner", a))
		})
	}
}

func (d *dao7DB) eventIDs() []int {
	d.t.Helper()
	rows, err := d.db.Pool().Query(d.ctx, `SELECT id FROM bgp_announcement_events ORDER BY id`)
	if err != nil {
		d.t.Fatal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int])
	if err != nil {
		d.t.Fatal(err)
	}
	d.t.Logf("announcement event ID set=%v", ids)
	return ids
}

func TestDao7bing_R5_AnnouncementEvents(t *testing.T) {
	d := newDao7DB(t)
	terminal := d.announcement("withdrawn")
	active := d.id(`INSERT INTO bgp_announcements (prefix, route_map, connector_id, status) VALUES ('203.0.113.0/24','RM',8,'active') RETURNING id`)
	b := d.attack(d.old)
	d.attach(b, active, d.old) // Guard 4 alone protects this ended attack.
	victim := d.attack(d.old)
	deleteNull := d.event(terminal, nil, d.old)
	deleteZero := d.event(terminal, 0, d.old)
	deleteVictim := d.event(terminal, victim, d.now) // Victim event, even if recent.
	keepNull := d.event(active, nil, d.old)
	keepAttack := d.event(active, b, d.old)
	keepRecent := d.event(terminal, nil, d.now)
	if got, want := d.eventIDs(), []int{deleteNull, deleteZero, deleteVictim, keepNull, keepAttack, keepRecent}; !reflect.DeepEqual(got, want) {
		t.Fatalf("fixture event set=%v, want %v", got, want)
	}
	before := d.snapshot("active announcement attack before", b)
	d.counts(before, map[string]int{"attacks": 1, "bgp_announcement_attacks": 1, "bgp_announcement_events": 1})
	d.clean(1)
	if got, want := d.eventIDs(), []int{keepNull, keepAttack, keepRecent}; !reflect.DeepEqual(got, want) {
		t.Errorf("remaining event set=%v, want %v", got, want)
	}
	d.unchanged(before, d.snapshot("active announcement attack after", b))
	d.counts(d.snapshot("victim after", victim), nil)
}

func TestDao7bing_R1b_TerminalExclusions(t *testing.T) {
	for _, name := range []string{"A2_xdrop_withdrawn", "A3_bgp_withdrawn"} {
		t.Run(name, func(t *testing.T) {
			d := newDao7DB(t)
			a := d.attack(d.old)
			want := map[string]int{"attacks": 1, "action_execution_log": 1}
			if name == "A2_xdrop_withdrawn" {
				d.log(a, 101, 7, "xdrop", "on_detected", "rule-1")
				d.rule(a, 101, "withdrawn")
				want["xdrop_active_rules"] = 1
			} else {
				d.log(a, 201, 8, "bgp", "on_detected", "198.51.100.0/24|RM")
				d.announcement("withdrawn") // No attachment, no withdrawal log.
			}
			d.counts(d.snapshot("before Cleaner", a), want)
			d.clean(1)
			d.counts(d.snapshot("after Cleaner", a), nil)
		})
	}
}

func TestDao7bing_R2b_CrossAction(t *testing.T) {
	d := newDao7DB(t)
	b := d.attack(d.old)
	d.log(b, 101, 7, "xdrop", "on_detected", "rule-1") // X
	d.log(b, 102, 7, "xdrop", "on_detected", "rule-1") // Y
	d.rule(b, 101, "withdrawn")
	d.log(b, 101, 7, "xdrop", "manual_override", "rule-1")
	before := d.snapshot("B7 before Cleaner", b)
	d.counts(before, map[string]int{"attacks": 1, "action_execution_log": 3, "xdrop_active_rules": 1})
	d.clean(0)
	d.unchanged(before, d.snapshot("B7 after Cleaner", b))
}

func TestDao7bing_R2c_BGPLogOnly(t *testing.T) {
	d := newDao7DB(t)
	b := d.attack(d.old)
	d.log(b, 201, 8, "bgp", "on_detected", "198.51.100.0/24|RM")
	var announcements int
	if err := d.db.Pool().QueryRow(d.ctx, `SELECT count(*) FROM bgp_announcements`).Scan(&announcements); err != nil {
		t.Fatal(err)
	}
	if announcements != 0 {
		t.Fatalf("fixture announcement count=%d, want 0", announcements)
	}
	before := d.snapshot("B8 before Cleaner", b)
	d.counts(before, map[string]int{"attacks": 1, "action_execution_log": 1})
	d.clean(0)
	d.unchanged(before, d.snapshot("B8 after Cleaner", b))
}

func TestDao7bing_R5b_EmptyVictims(t *testing.T) {
	d := newDao7DB(t)
	p := d.announcement("withdrawn")
	e := d.event(p, nil, d.old)
	if got := d.eventIDs(); !reflect.DeepEqual(got, []int{e}) {
		t.Fatalf("fixture event set=%v, want [%d]", got, e)
	}
	var attacks int
	if err := d.db.Pool().QueryRow(d.ctx, `SELECT count(*) FROM attacks`).Scan(&attacks); err != nil {
		t.Fatal(err)
	}
	if attacks != 0 {
		t.Fatalf("fixture attacks=%d, want 0", attacks)
	}
	d.clean(0)
	if got := d.eventIDs(); len(got) != 0 {
		t.Errorf("remaining event set=%v, want empty", got)
	}
}

func TestDao7bing_R8_Batches(t *testing.T) {
	d := newDao7DB(t)
	previous := attackBatchLimit
	attackBatchLimit = 2
	t.Cleanup(func() { attackBatchLimit = previous })
	ids := []int{d.terminalAttack(), d.terminalAttack(), d.terminalAttack()}
	d.counts(d.snapshot("three complete fixtures", ids...), map[string]int{"attacks": 3, "action_execution_log": 12, "xdrop_active_rules": 3, "scheduled_actions": 3, "bgp_announcement_attacks": 3, "bgp_announcement_events": 3, "action_manual_overrides": 3, "actions_log": 3})
	d.clean(3)
	d.counts(d.snapshot("one round after two batches", ids...), nil)
}

// Exact query from postgres.actionExecLogRepo.AllTargetsDone, prefixed by EXPLAIN.
const dao7AllTargetsDone = `WITH latest AS (
	 SELECT DISTINCT ON (COALESCE(connector_id, 0))
	        COALESCE(connector_id, 0) AS target, status, executed_at, id
	 FROM action_execution_log
	 WHERE attack_id=$1 AND action_id=$2 AND trigger_phase=$3 AND status <> 'skipped'
	 ORDER BY COALESCE(connector_id, 0), executed_at DESC, id DESC
	)
	SELECT COALESCE(bool_and(status IN ('success','scheduled')), false)
	FROM latest l WHERE target <> 0 OR NOT EXISTS (
	 SELECT 1 FROM latest newer WHERE newer.target <> 0
	 AND (newer.executed_at, newer.id) > (l.executed_at, l.id)
	)`

func (d *dao7DB) indexSet() []string {
	d.t.Helper()
	rows, err := d.db.Pool().Query(d.ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname='public' AND tablename='action_execution_log' AND indexname='idx_action_exec_log_attack' ORDER BY indexdef`)
	if err != nil {
		d.t.Fatal(err)
	}
	defs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		d.t.Fatal(err)
	}
	d.t.Logf("index definition set=%v", defs)
	return defs
}

func TestDao7bing_R6_Index(t *testing.T) {
	d := newDao7DB(t)
	defs := d.indexSet()
	if len(defs) != 1 || !strings.Contains(defs[0], "(attack_id, action_id, trigger_phase)") {
		t.Errorf("index definition set=%v, want exactly one (attack_id, action_id, trigger_phase) index", defs)
	}
	a := d.attack(d.old)
	d.log(a, 101, 7, "xdrop", "on_detected", "rule-1")
	tx, err := d.db.Pool().Begin(d.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(d.ctx)
	if _, err := tx.Exec(d.ctx, "SET LOCAL enable_seqscan = off"); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(d.ctx, "EXPLAIN "+dao7AllTargetsDone, a, 101, "on_detected")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range plan {
		t.Log(line)
		if strings.Contains(line, "Index") && strings.Contains(line, "idx_action_exec_log_attack") {
			found = true
		}
	}
	if !found {
		t.Errorf("AllTargetsDone plan lacks Index scan idx_action_exec_log_attack: %s", strings.Join(plan, "\n"))
	}
}

func TestDao7bing_R7_MigrationIdempotence(t *testing.T) {
	d := newDao7DB(t)
	before := d.indexSet()
	for i := 1; i <= 2; i++ {
		d.migrate()
		after := d.indexSet()
		if len(after) != 1 || !reflect.DeepEqual(before, after) {
			t.Errorf("migration %d index set=%v, initial=%v; want one unchanged index", i, after, before)
		}
		t.Log(fmt.Sprintf("AutoMigrate repeat %d: index count=%d", i, len(after)))
	}
}

func TestDao7bing_R2d_XDropWithdrawalType(t *testing.T) {
	d := newDao7DB(t)
	attack := d.attack(d.old)
	d.log(attack, 101, 7, "xdrop", "on_detected", "rule-1")
	d.log(attack, 302, 7, "webhook", "on_expired", "rule-1")
	// Matching the three identity fields is insufficient: only an xDrop
	// withdrawal can discharge this log-only xDrop claim.
	rows := d.snapshot("R2d mixed action types", attack)
	d.counts(rows, map[string]int{"attacks": 1, "action_execution_log": 2})
	d.clean(0)
	d.unchanged(rows, d.snapshot("R2d claim retained", attack))
}

func TestDao7bing_R1c_BGPNoSeparator(t *testing.T) {
	d := newDao7DB(t)
	attack := d.attack(d.old)
	d.log(attack, 201, 8, "bgp", "on_detected", "198.51.100.0/24")
	d.counts(d.snapshot("R1c malformed recovery key", attack), map[string]int{"attacks": 1, "action_execution_log": 1})
	var announcements int
	if err := d.db.Pool().QueryRow(d.ctx, "SELECT count(*) FROM bgp_announcements").Scan(&announcements); err != nil {
		t.Fatal(err)
	}
	if announcements != 0 {
		t.Fatalf("fixture announcements=%d, want 0", announcements)
	}
	d.clean(1)
	d.counts(d.snapshot("R1c non-recoverable log removed", attack), nil)
}

// Observe only the production cleanup pool; fixture queries and migrations use
// d.db.Pool(). Cancellation is synchronous at a selected query, without timers.
type dao7CleanupTrace struct {
	mu           sync.Mutex
	queries      []string
	selects      int
	cancelSelect int
}

func (tr *dao7CleanupTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	switch {
	case strings.HasPrefix(q.SQL, "SELECT id FROM attacks a WHERE"):
		tr.queries = append(tr.queries, "victims")
		tr.selects++
		if tr.selects == tr.cancelSelect {
			failed, cancel := context.WithCancel(ctx)
			cancel()
			return failed
		}
	case strings.HasPrefix(q.SQL, "DELETE FROM bgp_announcement_events e WHERE"):
		tr.queries = append(tr.queries, "event sweep")
	}
	return ctx
}

func (*dao7CleanupTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (tr *dao7CleanupTrace) check(t *testing.T, wantSelects, wantSweeps int) {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	counts := map[string]int{"victims": 0, "event sweep": 0}
	for _, query := range tr.queries {
		counts[query]++
	}
	want := map[string]int{"victims": wantSelects, "event sweep": wantSweeps}
	t.Logf("cleanup query counts=%v; sequence=%v", counts, tr.queries)
	if !reflect.DeepEqual(counts, want) {
		t.Errorf("cleanup query counts=%v, want %v", counts, want)
	}
}

func (d *dao7DB) tracedCleaner(tr *dao7CleanupTrace) *Cleaner {
	d.t.Helper()
	cfg := d.db.Pool().Config()
	cfg.ConnConfig.Tracer = tr
	pool, err := pgxpool.NewWithConfig(d.ctx, cfg)
	if err != nil {
		d.t.Fatal(err)
	}
	d.t.Cleanup(pool.Close)
	return New(pool, Config{AttacksDays: 30})
}

func dao7UseBatchLimit(t *testing.T, limit int) {
	t.Helper()
	saved := attackBatchLimit
	attackBatchLimit = limit
	t.Cleanup(func() { attackBatchLimit = saved })
}

func TestDao7bing_R8b_EventSweepOnce(t *testing.T) {
	d := newDao7DB(t)
	dao7UseBatchLimit(t, 2)
	attacks := []int{d.terminalAttack(), d.terminalAttack(), d.terminalAttack()}
	trace := &dao7CleanupTrace{}
	deleted, err := d.tracedCleaner(trace).deleteOldAttacks(d.ctx, 30)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 3 {
		t.Errorf("deleted attacks=%d, want 3", deleted)
	}
	d.counts(d.snapshot("R8b both batches committed", attacks...), nil)
	trace.check(t, 2, 1)
}

type dao7LogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *dao7LogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *dao7LogBuffer) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// These tests are deliberately not parallel: log output and the batch limit
// are package-wide. Restore the writer even if the tested operation calls Fatal.
func dao7CaptureLogs(t *testing.T, operation func()) string {
	t.Helper()
	writer := log.Writer()
	defer log.SetOutput(writer)
	buffer := &dao7LogBuffer{}
	log.SetOutput(buffer)
	operation()
	output := buffer.text()
	t.Logf("captured retention INFO:\n%s", output)
	return output
}

func dao7InfoLine(t *testing.T, output, prefix, expected string) {
	t.Helper()
	var matches []string
	for _, line := range strings.Split(output, "\n") {
		if offset := strings.Index(line, prefix); offset >= 0 {
			matches = append(matches, line[offset:])
		}
	}
	if !reflect.DeepEqual(matches, []string{expected}) {
		t.Errorf("INFO %q lines=%v, want exactly [%s]", prefix, matches, expected)
	}
}

func dao7TableLogs(t *testing.T, output string, want map[string]int) {
	t.Helper()
	for _, table := range dao7Tables {
		prefix := "retention: " + table + " deleted "
		dao7InfoLine(t, output, prefix, fmt.Sprintf("%s%d rows", prefix, want[table]))
	}
}

func TestDao7bing_R9_KeptAndPerTableLogs(t *testing.T) {
	d := newDao7DB(t)
	victim := d.terminalAttack()
	activeRule, recoverable := d.attack(d.old), d.attack(d.old)
	d.rule(activeRule, 101, "active")
	d.log(recoverable, 101, 7, "xdrop", "confirmed", "rule-1")
	survivors := []int{activeRule, recoverable, d.attack(nil), d.attack(d.now.Add(-time.Hour))}
	before := d.snapshot("R9 protected and time-ineligible attacks", survivors...)
	d.counts(before, map[string]int{"attacks": 4, "action_execution_log": 1, "xdrop_active_rules": 1})
	output := dao7CaptureLogs(t, func() { d.clean(1) })
	dao7InfoLine(t, output, "retention: kept ", "retention: kept 2 ended attacks with unfinished state")
	dao7TableLogs(t, output, map[string]int{"attacks": 1, "action_execution_log": 4, "xdrop_active_rules": 1, "scheduled_actions": 1, "bgp_announcement_attacks": 1, "bgp_announcement_events": 1, "action_manual_overrides": 1, "actions_log": 1})
	d.counts(d.snapshot("R9 deleted victim", victim), nil)
	d.unchanged(before, d.snapshot("R9 survivors unchanged", survivors...))
}

func TestDao7bing_R10_PartialFailureLogsCommittedBatch(t *testing.T) {
	for _, entry := range []string{"returned_count", "cleanup_total"} {
		t.Run(entry, func(t *testing.T) {
			d := newDao7DB(t)
			dao7UseBatchLimit(t, 2)
			ids := []int{d.terminalAttack(), d.terminalAttack(), d.terminalAttack()}
			// The independent first-batch sweep must not remove the third
			// attack's event, so its whole fixture can remain byte-for-byte intact.
			d.exec(`UPDATE bgp_announcement_events SET created_at=$1 WHERE attack_id=$2`, d.now, ids[2])
			third := d.snapshot("R10 third batch fixture", ids[2])
			d.counts(third, map[string]int{"attacks": 1, "action_execution_log": 4, "xdrop_active_rules": 1, "scheduled_actions": 1, "bgp_announcement_attacks": 1, "bgp_announcement_events": 1, "action_manual_overrides": 1, "actions_log": 1})
			trace := &dao7CleanupTrace{cancelSelect: 2}
			cleaner := d.tracedCleaner(trace)
			output := dao7CaptureLogs(t, func() {
				if entry == "cleanup_total" {
					cleaner.cleanup(d.ctx)
					return
				}
				deleted, err := cleaner.deleteOldAttacks(d.ctx, 30)
				t.Logf("partial batch result=(%d, %v)", deleted, err)
				if deleted != 2 || err == nil {
					t.Errorf("partial batch result=(%d, %v), want (2, error)", deleted, err)
				}
			})
			trace.check(t, 2, 1)
			d.counts(d.snapshot("R10 first batch gone", ids[0], ids[1]), nil)
			d.unchanged(third, d.snapshot("R10 failed batch intact", ids[2]))
			dao7TableLogs(t, output, map[string]int{"attacks": 2, "action_execution_log": 8, "xdrop_active_rules": 2, "scheduled_actions": 2, "bgp_announcement_attacks": 2, "bgp_announcement_events": 2, "action_manual_overrides": 2, "actions_log": 2})
			if entry == "cleanup_total" {
				if strings.Count(output, "retention: attacks cleanup error:") != 1 {
					t.Errorf("expected one second-batch error log: %s", output)
				}
				dao7InfoLine(t, output, "retention: cleanup complete, ", "retention: cleanup complete, 2 total rows deleted")
				if strings.Contains(output, "nothing to delete") {
					t.Errorf("committed deletions reported as nothing: %s", output)
				}
			}
		})
	}
}
