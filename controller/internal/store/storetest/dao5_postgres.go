package storetest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RunDao5CreateContention exercises real sessions; the factory uses the normal
// contract database/DSN lifecycle. Mock arms of C2 live in runDao5Contract.
func RunDao5CreateContention(t *testing.T, open func(*testing.T) (store.AttackRepo, *pgxpool.Pool)) {
	for _, arm := range []string{"commit", "rollback", "deadline_cleanup"} {
		t.Run("Attacks/Dao5_C2_Contention/"+arm, func(t *testing.T) {
			repo, pool := open(t)
			bounded, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			connect := func(name string) *pgx.Conn {
				cfg := pool.Config().ConnConfig.Copy()
				cfg.RuntimeParams["application_name"] = name
				conn, err := pgx.ConnectConfig(bounded, cfg)
				check(t, err)
				t.Cleanup(func() {
					c, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					check(t, conn.Close(c))
				})
				return conn
			}
			holder, observer := connect("dao5-holder"), connect("dao5-observer")
			probe, err := pool.Acquire(bounded)
			check(t, err)
			pid := probe.Conn().PgConn().PID()
			probe.Release()
			a := store.Attack{DstIP: "192.0.2.99", Direction: "receives", DecoderFamily: "udp", StartedAt: stamp(0).Add(123456789 * time.Nanosecond)}
			key := fmt.Sprintf("%s|%s|%s|%d", a.DstIP, a.Direction, a.DecoderFamily, a.StartedAt.UnixMicro())
			tx, err := holder.BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			check(t, err)
			defer tx.Rollback(context.Background())
			_, err = tx.Exec(bounded, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key)
			check(t, err)
			var firstID int
			err = tx.QueryRow(bounded, `INSERT INTO attacks(dst_ip,direction,decoder_family,started_at) VALUES($1::inet,$2,$3,$4) RETURNING id`, a.DstIP, a.Direction, a.DecoderFamily, a.StartedAt).Scan(&firstID)
			check(t, err)
			createCtx, stopCreate := context.WithTimeout(context.Background(), 5*time.Second)
			defer stopCreate()
			deadline, _ := createCtx.Deadline()
			type result struct {
				id       int
				err      error
				returned time.Time
			}
			done := make(chan result, 1)
			go func() { id, err := repo.Create(createCtx, &a); done <- result{id, err, time.Now()} }()
			// An independent server-side observer proves that session 2 is
			// waiting for this holder's advisory lock. No fixed sleep/barrier guess.
			for {
				select {
				case got := <-done:
					t.Fatalf("Create returned before lock holder ended / before observed wait: %+v", got)
				default:
				}
				var waiting bool
				err = observer.QueryRow(createCtx, `SELECT EXISTS (
				 SELECT 1 FROM pg_locks w JOIN pg_locks h
				 ON w.locktype=h.locktype AND w.database IS NOT DISTINCT FROM h.database
				 AND w.classid=h.classid AND w.objid=h.objid AND w.objsubid=h.objsubid
				 JOIN pg_stat_activity s ON s.pid=w.pid
				 WHERE w.pid=$1 AND h.pid=$2 AND w.locktype='advisory'
				 AND NOT w.granted AND h.granted AND s.wait_event_type='Lock')`, pid, holder.PgConn().PID()).Scan(&waiting)
				check(t, err)
				if waiting {
					break
				}
			}
			t.Logf("independent observer confirmed pid=%d waits on holder pid=%d advisory lock", pid, holder.PgConn().PID())
			if arm == "deadline_cleanup" {
				got := <-done
				if got.err == nil || got.returned.Before(deadline) || got.returned.After(deadline.Add(time.Second)) {
					t.Fatalf("Create deadline: err=%v returned=%v deadline=%v (tolerance 1s)", got.err, got.returned, deadline)
				}
				// Keep holder open throughout cleanup observation. A fresh context
				// covers pgx's asynchronous cancellation/connection destruction.
				cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
				defer stop()
				for {
					var inTransaction int
					err = observer.QueryRow(cleanup, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name='dao5-create' AND xact_start IS NOT NULL`).Scan(&inTransaction)
					check(t, err)
					if inTransaction == 0 {
						break
					}
				}
				acquired, err := pool.Acquire(cleanup)
				check(t, err)
				status := acquired.Conn().PgConn().TxStatus()
				acquired.Release()
				if status != 'I' {
					t.Fatalf("pool reused connection in transaction: TxStatus=%c", status)
				}
				t.Log("bounded independent observation: tested sessions have no transaction; acquired pooled connection is idle")
				return
			}
			ending := time.Now()
			if arm == "commit" {
				check(t, tx.Commit(bounded))
			} else {
				check(t, tx.Rollback(bounded))
			}
			got := <-done
			check(t, got.err)
			if !got.returned.After(ending) {
				t.Fatalf("Create returned=%v before holder end began=%v", got.returned, ending)
			}
			if arm == "commit" && got.id != firstID {
				t.Errorf("committed identity: got ID %d; want %d", got.id, firstID)
			}
			if arm == "rollback" && got.id == firstID {
				t.Errorf("rolled-back ID reused: %d", got.id)
			}
			var count int
			err = observer.QueryRow(bounded, `SELECT count(*) FROM attacks WHERE dst_ip=$1::inet AND direction=$2 AND decoder_family=$3 AND started_at=$4 AND ended_at IS NULL`, a.DstIP, a.Direction, a.DecoderFamily, a.StartedAt).Scan(&count)
			check(t, err)
			equal(t, count, 1)
		})
	}
}
