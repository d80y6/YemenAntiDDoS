package postgres

import (
	"context"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func TestDao13b_DB(t *testing.T) {
	repo := newPostgresContractBackend(t).Store().Users()
	ctx := context.Background()
	id, err := repo.Create(ctx, &store.User{Username: "dao13b-user", Password: "fixture-hash", Role: "admin", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	u, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	byName, err := repo.GetByUsername(ctx, u.Username)
	if err != nil {
		t.Fatal(err)
	}
	first := u.UpdatedAt.UnixMicro()
	if byName == nil || first != byName.UpdatedAt.UnixMicro() {
		t.Fatalf("Get and GetByUsername revisions differ: user=%+v byName=%+v", u, byName)
	}
	seen := map[int64]bool{first: true}
	if _, err := repo.Create(ctx, &store.User{Username: "dao13b-peer", Password: "fixture-hash", Role: "admin", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		u.Role = "viewer"
		if err := repo.Update(ctx, u); err != nil {
			t.Fatal(err)
		}
		u, err = repo.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		rev := u.UpdatedAt.UnixMicro()
		if seen[rev] {
			t.Fatalf("update %d reused revision %d in this execution", i+1, rev)
		}
		seen[rev] = true
	}
}
