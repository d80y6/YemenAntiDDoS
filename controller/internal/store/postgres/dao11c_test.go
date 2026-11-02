package postgres

import (
	"context"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestDao11c_G6a_FullASN(t *testing.T) {
	db := newPostgresContractBackend(t).Store().(*PGStore)
	ctx := context.Background()
	id, err := db.BGPConnectors().Create(ctx, &store.BGPConnector{Name: "dao11c-max", BGPASN: 4294967295, VtyshPath: "/usr/bin/vtysh", AddressFamily: "auto", Enabled: true})
	if err != nil {
		t.Fatalf("create ASN 4294967295: %v", err)
	}
	got, err := db.BGPConnectors().Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.BGPASN != 4294967295 {
		t.Fatalf("ASN=%d want=4294967295", got.BGPASN)
	}
}

func TestDao11c_G6b_MigrateExistingASN(t *testing.T) {
	db := newPostgresContractBackend(t).Store().(*PGStore)
	ctx := context.Background()
	if _, err := db.Pool().Exec(ctx, `ALTER TABLE bgp_connectors ALTER COLUMN bgp_asn TYPE INT`); err != nil {
		t.Fatal(err)
	}
	assertType := func(want string) {
		t.Helper()
		var got string
		err := db.Pool().QueryRow(ctx, `SELECT format_type(atttypid, atttypmod) FROM pg_attribute WHERE attrelid='bgp_connectors'::regclass AND attname='bgp_asn'`).Scan(&got)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("bgp_asn type=%s want=%s", got, want)
		}
	}
	assertType("integer")
	id, err := db.BGPConnectors().Create(ctx, &store.BGPConnector{Name: "dao11c-existing", BGPASN: 65000, VtyshPath: "/usr/bin/vtysh", AddressFamily: "auto", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ret := RetentionConfig{TSStatsDays: 7, TSStatsCompressDays: 1, TSStatsCaggDays: 90, FlowLogsDays: 7, FlowLogsCompressDays: 1}
	if err := db.AutoMigrate(ctx, ret); err != nil {
		t.Fatal(err)
	}
	assertType("bigint")
	got, err := db.BGPConnectors().Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.BGPASN != 65000 {
		t.Fatalf("existing ASN=%d want=65000", got.BGPASN)
	}
	if err := db.AutoMigrate(ctx, ret); err != nil {
		t.Fatal(err)
	}
	assertType("bigint")
}
