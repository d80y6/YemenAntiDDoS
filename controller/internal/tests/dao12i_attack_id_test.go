package tests

import (
	"context"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func dao12iCheck(t *testing.T, name string, got, want any) {
	t.Helper()
	if got != want {
		t.Errorf("ASSERT %s FAIL: got=%v want=%v", name, got, want)
		return
	}
	t.Logf("ASSERT %s PASS: got=%v want=%v", name, got, want)
}

func TestDao12i_G1(t *testing.T) {
	ctx := context.Background()
	attack := func(dst string) store.Attack {
		return store.Attack{DstIP: dst, Direction: "inbound", DecoderFamily: "udp", StartedAt: time.Unix(1700000000, 123456789)}
	}
	create := func(t *testing.T, r *mockAttackRepo, dst string) int {
		t.Helper()
		a := attack(dst)
		id, err := r.Create(ctx, &a)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	checkGet := func(t *testing.T, r *mockAttackRepo, name string, id int, dst string) {
		t.Helper()
		got, err := r.Get(ctx, id)
		if err != nil || got == nil {
			t.Fatalf("%s Get(%d): attack=%v err=%v", name, id, got, err)
		}
		dao12iCheck(t, name+".DstIP", got.DstIP, dst)
	}
	t.Run("SeededGap", func(t *testing.T) {
		r := &mockAttackRepo{}
		seed := attack("192.0.2.1")
		seed.ID = 2
		r.appendAttacks(seed)
		id := create(t, r, "192.0.2.2")
		dao12iCheck(t, "G1.SeededGap.ID", id, 3)
		dao12iCheck(t, "G1.SeededGap.NoCollision", id != seed.ID, true)
		checkGet(t, r, "G1.SeededGap", id, "192.0.2.2")
	})
	t.Run("SeededExpired", func(t *testing.T) {
		r := &mockAttackRepo{}
		seed := attack("192.0.2.1")
		seed.ID = 1
		ended := seed.StartedAt.Add(time.Minute)
		seed.EndedAt = &ended
		r.appendExpiredAttacks(seed)
		id := create(t, r, "192.0.2.2")
		dao12iCheck(t, "G1.SeededExpired.ID", id, 2)
		dao12iCheck(t, "G1.SeededExpired.NoCollision", id != seed.ID, true)
		checkGet(t, r, "G1.SeededExpired", id, "192.0.2.2")
	})
	t.Run("Mixed", func(t *testing.T) {
		r := &mockAttackRepo{}
		active, expired := attack("192.0.2.1"), attack("192.0.2.2")
		active.ID, expired.ID = 5, 9
		ended := expired.StartedAt.Add(time.Minute)
		expired.EndedAt = &ended
		r.appendAttacks(active)
		r.appendExpiredAttacks(expired)
		dao12iCheck(t, "G1.Mixed.InitialID", create(t, r, "192.0.2.3"), 10)
		active.ID, active.DstIP = 20, "192.0.2.4"
		r.appendAttacks(active)
		dao12iCheck(t, "G1.Mixed.ReseededID", create(t, r, "192.0.2.5"), 21)
	})
	t.Run("Sequential", func(t *testing.T) {
		r := &mockAttackRepo{}
		for i, dst := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
			dao12iCheck(t, "G1.Sequential.ID", create(t, r, dst), i+1)
		}
	})
	t.Run("Dedup", func(t *testing.T) {
		r := &mockAttackRepo{}
		first := create(t, r, "192.0.2.1")
		before, err := r.Count(ctx, store.AttackFilter{})
		if err != nil {
			t.Fatal(err)
		}
		second := create(t, r, "192.0.2.1")
		after, err := r.Count(ctx, store.AttackFilter{})
		if err != nil {
			t.Fatal(err)
		}
		dao12iCheck(t, "G1.Dedup.ID", second, first)
		dao12iCheck(t, "G1.Dedup.InitialCount", before, 1)
		dao12iCheck(t, "G1.Dedup.Count", after, before)
	})
}
