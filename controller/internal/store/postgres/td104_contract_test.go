package postgres

import (
	"github.com/d80y6/YemenDDoS/controller/internal/store/storetest"
	"os"
	"testing"
)

func TestTD104_Contract_Postgres(t *testing.T) {
	if os.Getenv("XSIGHT_TEST_ADMIN_DSN") == "" {
		t.Skip("XSIGHT_TEST_ADMIN_DSN is not set")
	}
	storetest.RunTD104Contract(t, newPostgresContractBackend)
}
