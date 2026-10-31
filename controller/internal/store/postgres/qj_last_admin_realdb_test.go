package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func qjCreate(t *testing.T, db *PGStore, name, role string, enabled bool) store.User {
	t.Helper()
	ctx := context.Background()
	id, err := db.Users().Create(ctx, &store.User{Username: name, Password: "fixture-hash", Role: role, Enabled: enabled})
	q0PGCheck(t, err)
	u, err := db.Users().Get(ctx, id)
	q0PGCheck(t, err)
	return *u
}

func qjWantError(t *testing.T, err, want error) {
	t.Helper()
	if err != want {
		t.Fatalf("error=%v want=%v", err, want)
	}
}

func qjUnchanged(t *testing.T, db *PGStore, before store.User) {
	t.Helper()
	got, err := db.Users().Get(context.Background(), before.ID)
	q0PGCheck(t, err)
	if got.Role != before.Role || got.Enabled != before.Enabled || !got.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("rejected write changed role/enabled/updated_at: got=%s/%t/%s want=%s/%t/%s",
			got.Role, got.Enabled, got.UpdatedAt, before.Role, before.Enabled, before.UpdatedAt)
	}
}

func TestQJLastAdminSequential(t *testing.T) {
	db := q0PG(t)
	ctx := context.Background()
	r := db.Users()
	a := qjCreate(t, db, "qj-A", "admin", true)
	b := qjCreate(t, db, "qj-B", "admin", true)
	c := qjCreate(t, db, "qj-C", "admin", false)
	d := qjCreate(t, db, "qj-D", "viewer", true)
	qjCreate(t, db, "qj-E", "Admin", true)
	qjCreate(t, db, "qj-F", "admin ", true)
	t.Run("DemoteA", func(t *testing.T) {
		a.Role = "viewer"
		qjWantError(t, r.Update(ctx, &a), nil)
	})
	t.Run("DemoteB", func(t *testing.T) {
		next := b
		next.Role = "viewer"
		qjWantError(t, r.Update(ctx, &next), store.ErrLastAdmin)
		qjUnchanged(t, db, b)
	})
	t.Run("DisableB", func(t *testing.T) {
		next := b
		next.Enabled = false
		qjWantError(t, r.Update(ctx, &next), store.ErrLastAdmin)
		qjUnchanged(t, db, b)
	})
	t.Run("DeleteB", func(t *testing.T) {
		qjWantError(t, r.Delete(ctx, b.ID), store.ErrLastAdmin)
		qjUnchanged(t, db, b)
	})
	t.Run("PasswordB", func(t *testing.T) {
		b.Password = "fixture-hash-updated"
		qjWantError(t, r.Update(ctx, &b), nil)
		got, err := r.Get(ctx, b.ID)
		q0PGCheck(t, err)
		if got.Password != b.Password || got.Role != "admin" || !got.Enabled {
			t.Fatal("password-only write was not preserved with enabled admin")
		}
	})
	t.Run("DeleteDisabledC", func(t *testing.T) { qjWantError(t, r.Delete(ctx, c.ID), nil) })
	t.Run("DeleteViewerD", func(t *testing.T) { qjWantError(t, r.Delete(ctx, d.ID), nil) })
	t.Run("Missing", func(t *testing.T) {
		missing := store.User{ID: -1, Username: "qj-missing", Password: "fixture-hash", Role: "viewer", Enabled: true}
		qjWantError(t, r.Update(ctx, &missing), nil)
		qjWantError(t, r.Delete(ctx, missing.ID), nil)
	})
	t.Run("PromoteA", func(t *testing.T) {
		a.Role = "admin"
		qjWantError(t, r.Update(ctx, &a), nil)
	})
	t.Run("DeleteBWithPeer", func(t *testing.T) { qjWantError(t, r.Delete(ctx, b.ID), nil) })
}

func TestQJLastAdminZeroStart(t *testing.T) {
	// A separate disposable database starts with zero counted users.
	db := q0PG(t)
	ctx := context.Background()
	g := qjCreate(t, db, "qj-G", "admin", false)
	h := qjCreate(t, db, "qj-H", "viewer", true)
	h.Role = "operator"
	qjWantError(t, db.Users().Update(ctx, &h), nil)
	got, err := db.Users().Get(ctx, h.ID)
	q0PGCheck(t, err)
	if got.Role != "operator" {
		t.Fatalf("H role=%q want=operator", got.Role)
	}
	qjWantError(t, db.Users().Delete(ctx, h.ID), nil)
	qjWantError(t, db.Users().Delete(ctx, g.ID), nil)
}

func qjLockWitness(t *testing.T, deleting bool) {
	t.Helper()
	db := q0PG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	a := qjCreate(t, db, "qj-A", "admin", true)
	b := qjCreate(t, db, "qj-B", "admin", true)
	tx, err := db.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	q0PGCheck(t, err)
	done := make(chan error, 1)
	started, finished := false, false
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
		cancel()
		if started && !finished {
			select {
			case <-done:
			case <-cleanup.Done():
				t.Error("worker did not finish after rollback/cancellation")
			}
		}
	}()
	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, userAdminLockKey)
	q0PGCheck(t, err)
	started = true
	go func() {
		if deleting {
			done <- db.Users().Delete(ctx, a.ID)
			return
		}
		next := a
		next.Role = "viewer"
		done <- db.Users().Update(ctx, &next)
	}()
	waitCtx, stopWait := context.WithTimeout(ctx, 5*time.Second)
	defer stopWait()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting int
		err := tx.QueryRow(waitCtx, `SELECT count(*) FROM pg_locks w JOIN pg_locks h USING (locktype, database, classid, objid, objsubid) WHERE w.locktype = 'advisory' AND NOT w.granted AND h.granted AND h.pid = pg_backend_pid()`).Scan(&waiting)
		if err != nil {
			t.Fatalf("same-key pg_locks witness within 5s: %v", err)
		}
		select {
		case err := <-done:
			finished = true
			t.Fatalf("worker returned before holder released same-key lock: %v", err)
		default:
		}
		if waiting >= 1 {
			t.Logf("same-key pg_locks waiting=%d; worker still blocked", waiting)
			break
		}
		select {
		case <-waitCtx.Done():
			t.Fatal("same-key pg_locks waiting=0; want >=1 within 5s")
		case <-tick.C:
		}
	}
	_, err = tx.Exec(ctx, `UPDATE users SET role='viewer' WHERE id=$1`, b.ID)
	q0PGCheck(t, err)
	q0PGCheck(t, tx.Commit(ctx))
	select {
	case err := <-done:
		finished = true
		qjWantError(t, err, store.ErrLastAdmin)
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not return within 5s after holder commit")
	}
	qjUnchanged(t, db, a)
}

func TestQJLastAdminLockUpdate(t *testing.T) { qjLockWitness(t, false) }
func TestQJLastAdminLockDelete(t *testing.T) { qjLockWitness(t, true) }

func TestQJLastAdminConcurrent(t *testing.T) {
	db := q0PG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	a := qjCreate(t, db, "qj-A", "admin", true)
	b := qjCreate(t, db, "qj-B", "admin", true)
	for round := 0; round < 20; round++ {
		if !t.Run(fmt.Sprintf("Round%02d", round), func(t *testing.T) {
			start, ready, done := make(chan struct{}), make(chan struct{}, 2), make(chan error, 2)
			for i, row := range []store.User{a, b} {
				go func(i int, row store.User) {
					ready <- struct{}{}
					<-start
					if round%2 == 1 && i == 1 {
						done <- db.Users().Delete(ctx, row.ID)
					} else {
						row.Role = "viewer"
						done <- db.Users().Update(ctx, &row)
					}
				}(i, row)
			}
			<-ready
			<-ready
			close(start)
			success, guarded := 0, 0
			for i := 0; i < 2; i++ {
				select {
				case err := <-done:
					switch {
					case err == nil:
						success++
					case errors.Is(err, store.ErrLastAdmin):
						guarded++
					default:
						t.Errorf("concurrent write: %v", err)
					}
				case <-ctx.Done():
					t.Fatal("concurrent workers timed out")
				}
			}
			var counted int
			q0PGCheck(t, db.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND enabled IS TRUE`).Scan(&counted))
			if success != 1 || guarded != 1 || counted != 1 {
				t.Fatalf("nil=%d ErrLastAdmin=%d counted=%d want=1/1/1", success, guarded, counted)
			}
			t.Logf("round=%d mixed=%t nil=%d ErrLastAdmin=%d counted=%d", round, round%2 == 1, success, guarded, counted)
			// Both workers have returned. Restore by direct SQL, including B's new id after deletion.
			tag, err := db.pool.Exec(ctx, `UPDATE users SET role='admin', enabled=true WHERE id IN ($1,$2)`, a.ID, b.ID)
			q0PGCheck(t, err)
			if tag.RowsAffected() == 1 {
				q0PGCheck(t, db.pool.QueryRow(ctx,
					`INSERT INTO users (username,password,role,enabled) VALUES ($1,$2,'admin',true) RETURNING id`,
					b.Username, "fixture-hash").Scan(&b.ID))
			} else if tag.RowsAffected() != 2 {
				t.Fatalf("reset rows=%d want=1 or 2", tag.RowsAffected())
			}
		}) {
			return
		}
	}
}
