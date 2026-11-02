package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// The runner supplies an isolated real database and the existing no-DSN skip.
type FuzhuoPostgres struct {
	Backend  Backend
	Pool     *pgxpool.Pool
	TestRepo store.BGPAnnouncementRepo
	TestPool *pgxpool.Pool // MaxConns=1 pins the observed PID to the tested call.
	Migrate  func(context.Context) error
}

func RunFuzhuoPostgres(t *testing.T, open func(*testing.T) FuzhuoPostgres) {
	t.Run("C3_LockThenRecheckStatus", func(t *testing.T) {
		f := open(t)
		s, ann, ids := fuzhuoSeed(t, f.Backend, true)
		bounded, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		connect := func() *pgx.Conn {
			c, err := pgx.ConnectConfig(bounded, f.Pool.Config().ConnConfig.Copy())
			check(t, err)
			t.Cleanup(func() { _ = c.Close(context.Background()) })
			return c
		}
		holder, observer := connect(), connect()
		probe, err := f.TestPool.Acquire(bounded)
		check(t, err)
		pid := probe.Conn().PgConn().PID()
		probe.Release()
		tx, err := holder.Begin(bounded)
		check(t, err)
		defer tx.Rollback(context.Background())
		var locked int
		check(t, tx.QueryRow(bounded, `SELECT id FROM bgp_announcements WHERE id=$1 FOR UPDATE`, ann).Scan(&locked))
		type result struct {
			r   store.BGPReconcileResult
			err error
		}
		done := make(chan result, 1)
		go func() { r, err := f.TestRepo.ReconcileAttachments(bounded, ann, ids, true); done <- result{r, err} }()
		for {
			select {
			case got := <-done:
				t.Fatalf("reconcile returned before observed lock wait: %+v", got)
			default:
			}
			var waiting bool
			check(t, observer.QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM pg_locks w WHERE w.pid=$1 AND NOT w.granted AND $2::int = ANY(pg_blocking_pids(w.pid)))`, pid, holder.PgConn().PID()).Scan(&waiting))
			if waiting {
				break
			}
		}
		t.Logf("independent pg_locks observer: tested pid=%d blocked by holder pid=%d", pid, holder.PgConn().PID())
		_, err = tx.Exec(bounded, `UPDATE bgp_announcements SET status='delayed' WHERE id=$1`, ann)
		check(t, err)
		check(t, tx.Commit(bounded))
		var got result
		select {
		case got = <-done:
		case <-bounded.Done():
			t.Fatal(bounded.Err())
		}
		check(t, got.err)
		equal(t, got.r.Skipped, "status=delayed")
		equal(t, got.r.NeedWithdraw, false)
		a, err := s.BGPAnnouncements().Get(bounded, ann)
		check(t, err)
		equal(t, a.Status, "delayed")
		equal(t, a.Refcount, 1)
		rows, err := s.BGPAnnouncements().ListAttacks(bounded, ann)
		check(t, err)
		equal(t, len(rows), 1)
		equal(t, rows[0].DetachedAt == nil, true)
	})
	for _, status := range []string{"withdrawn", "active"} {
		t.Run("C5_Backfill_"+status, func(t *testing.T) {
			f := open(t)
			s, ann, ids := fuzhuoSeed(t, f.Backend, false)
			a, err := s.BGPAnnouncements().Get(ctx, ann)
			check(t, err)
			if status == "withdrawn" {
				_, _, err = s.BGPAnnouncements().ForceWithdraw(ctx, ann)
				check(t, err)
				check(t, s.BGPAnnouncements().MarkWithdrawn(ctx, ann, dao5bCurrentGen(t, s.BGPAnnouncements(), ann)))
			}
			b := seedAttack(t, s, store.Attack{})
			_, err = s.ActionExecLog().Create(ctx, &store.ActionExecutionLog{AttackID: b, ActionID: *a.FirstActionID, ActionType: "bgp", ConnectorID: &a.ConnectorID, TriggerPhase: "on_detected", Status: "success", ExternalRuleID: a.Prefix + "|" + a.RouteMap})
			check(t, err)
			var prior int
			check(t, f.Pool.QueryRow(ctx, `SELECT count(*) FROM bgp_announcement_attacks WHERE announcement_id=$1 AND attack_id=$2`, ann, b).Scan(&prior))
			equal(t, prior, 0)
			check(t, f.Migrate(ctx))
			rows, err := s.BGPAnnouncements().ListAttacks(ctx, ann)
			check(t, err)
			attached := map[int]bool{}
			for _, r := range rows {
				if r.DetachedAt == nil {
					attached[r.AttackID] = true
				}
			}
			if status == "withdrawn" {
				equal(t, attached[b], false)
				return
			}
			equal(t, attached, map[int]bool{ids[0]: true})
			a, err = s.BGPAnnouncements().Get(ctx, ann)
			check(t, err)
			equal(t, a.Refcount, 1)
			_, err = f.Pool.Exec(ctx, "INSERT INTO bgp_announcement_attacks(announcement_id,attack_id,action_id) VALUES($1,$2,$3)", ann, b, *a.FirstActionID)
			check(t, err)
			r, err := s.BGPAnnouncements().ReconcileAttachments(ctx, ann, nil, true)
			check(t, err)
			equal(t, r.RefcountBefore, 1)
			equal(t, r.RefcountAfter, 2)
			equal(t, r.NeedWithdraw, false)
			a, err = s.BGPAnnouncements().Get(ctx, ann)
			check(t, err)
			equal(t, a.Refcount, 2)
			equal(t, a.Status, "active")
		})
	}
}
