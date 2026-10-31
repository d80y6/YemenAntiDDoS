package tests

import (
	"github.com/littlewolf9527/xsight/controller/internal/store/storetest"
	"testing"
)

func TestTD104_Contract_Mock(t *testing.T) {
	storetest.RunTD104Contract(t, func(t *testing.T) storetest.Backend { return &mockContractBackend{ms: NewMockStore()} })
}
