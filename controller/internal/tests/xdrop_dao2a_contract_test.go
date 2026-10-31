package tests

import (
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store/storetest"
)

func TestD2A_CountLiveContract(t *testing.T) {
	storetest.RunXDrop2AContract(t, func(t *testing.T) storetest.Backend {
		return &mockContractBackend{ms: NewMockStore()}
	})
}
