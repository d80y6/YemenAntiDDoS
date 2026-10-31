package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/ingestion"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func dao14PG(t *testing.T) *PGStore {
	t.Helper()
	return newPostgresContractBackend(t).(*postgresContractBackend).db
}
func dao14PGPoint(node, prefix, ip string) store.StatPoint {
	p := store.StatPoint{Time: time.Now(), NodeID: node, Direction: "receives", PPS: 10}
	if prefix != "" {
		p.Prefix = &prefix
	}
	if ip != "" {
		p.DstIP = &ip
	}
	return p
}
func dao14PGCount(t *testing.T, db *PGStore, node string) int {
	t.Helper()
	var count int
	if err := db.Pool().QueryRow(context.Background(), "SELECT count(*) FROM ts_stats WHERE node_id=$1", node).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestDao14a2_PG_G1p(t *testing.T) {
	for _, c := range []struct{ name, prefix, ip string }{
		{"V4Net", "192.0.2.0/24", "192.0.2.1"}, {"V4Host", "192.0.2.10/32", "192.0.2.10"}, {"V4Zero", "0.0.0.0/0", "0.0.0.0"},
		{"V6Net", "2001:db8::/32", "2001:db8::1"}, {"V6Host", "2001:db8::1/128", "2001:db8::1"}, {"V6Zero", "::/0", "::"}, {"Mapped24", "192.0.2.0/24", "192.0.2.1"},
	} {
		t.Run("Good/"+c.name, func(t *testing.T) {
			db := dao14PG(t)
			ctx := context.Background()
			if err := db.Stats().BulkInsert(ctx, []store.StatPoint{dao14PGPoint("good", c.prefix, c.ip)}); err != nil {
				t.Fatal(err)
			}
			var prefix, ip string
			if err := db.Pool().QueryRow(ctx, "SELECT prefix::text, host(dst_ip) FROM ts_stats WHERE node_id=$1", "good").Scan(&prefix, &ip); err != nil {
				t.Fatal(err)
			}
			if prefix != c.prefix || ip != c.ip {
				t.Errorf("roundtrip=%q/%q want %q/%q", prefix, ip, c.prefix, c.ip)
			}
		})
	}
	for _, c := range []struct{ name, prefix, ip string }{
		{"Len3", "?c00002/24", ""}, {"Len33", "192.0.2.0/33", ""}, {"HostBits", "192.0.2.5/24", ""}, {"IPLen3", "", "?c00002"}, {"IPNil", "", "<nil>"},
	} {
		t.Run("Bad/"+c.name, func(t *testing.T) {
			db := dao14PG(t)
			if err := db.Stats().BulkInsert(context.Background(), []store.StatPoint{dao14PGPoint("bad", c.prefix, c.ip)}); err == nil {
				t.Fatal("malformed string accepted")
			}
			if n := dao14PGCount(t, db, "bad"); n != 0 {
				t.Errorf("bad rows=%d", n)
			}
		})
		t.Run("Atomic/"+c.name, func(t *testing.T) {
			db := dao14PG(t)
			pts := []store.StatPoint{dao14PGPoint("good", "198.51.100.0/24", "198.51.100.1"), dao14PGPoint("bad", c.prefix, c.ip)}
			if err := db.Stats().BulkInsert(context.Background(), pts); err == nil {
				t.Fatal("mixed batch accepted")
			}
			if n := dao14PGCount(t, db, "good"); n != 0 {
				t.Errorf("atomicity: good rows=%d", n)
			}
		})
	}
}

func TestDao14a2_PG_G1q(t *testing.T) {
	db := dao14PG(t)
	ctx, cancel := context.WithCancel(context.Background())
	w := ingestion.NewDBWriter(nil, db.Stats(), 50*time.Millisecond)
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	w.Enqueue([]store.StatPoint{dao14PGPoint("good", "198.51.100.0/24", ""), dao14PGPoint("poison", "192.0.2.5/24", "")})
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-tick.C:
			if dao14PGCount(t, db, "poison") != 0 {
				t.Fatal("poison row committed")
			}
			if dao14PGCount(t, db, "good") >= 1 {
				return
			}
		case <-deadline.C:
			t.Fatal("good node did not commit within 5s")
		}
	}
}
