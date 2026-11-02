package postgres

import (
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store/storetest"
)

func TestDao13c_F5_Postgres(t *testing.T) { storetest.RunDao13cF5(t, dao5bOpenPG) }
func TestDao13c_K2_Postgres(t *testing.T) { storetest.RunDao13cK2(t, dao5bOpenPG) }
