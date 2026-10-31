package tests

import (
	"context"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/store/storetest"
)

func dao5bCurrentGen(t *testing.T, r store.BGPAnnouncementRepo, id int) int {
	t.Helper()
	a, err := r.Get(context.Background(), id)
	if err != nil || a == nil {
		t.Fatalf("announcement %d: %+v %v", id, a, err)
	}
	return a.Gen
}

type dao5bMockBackend struct{ *mockContractBackend }

func (b dao5bMockBackend) SetGeneration(id, gen int) error {
	r := b.ms.bgpAnnouncements
	r.mu.Lock()
	defer r.mu.Unlock()
	r.findByIDLocked(id).Gen = gen
	return nil
}

func dao5bOpenMock(t *testing.T) storetest.Dao5bBackend {
	return dao5bMockBackend{&mockContractBackend{ms: NewMockStore()}}
}

func TestDao5b_G3_Mock(t *testing.T) { storetest.RunDao5bG3(t, dao5bOpenMock) }

func TestDao5b_G2_Mock(t *testing.T) { storetest.RunDao5bG2(t, dao5bOpenMock) }
func TestDao5b_G4_Mock(t *testing.T) { storetest.RunDao5bG4(t, dao5bOpenMock) }

func TestDao11j_C1_Mock(t *testing.T) { storetest.RunDao11jC1(t, dao5bOpenMock) }
