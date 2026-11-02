package action

import (
	"context"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/storetest"
)

func TestDao5_C1_V3Schedules(t *testing.T) {
	for _, status := range []string{"missing", "pending", "executing", "cancelled", "completed", "failed"} {
		t.Run(status, func(t *testing.T) {
			s := newV3Store("")
			if status != "missing" {
				s.schedules = []store.ScheduledAction{{ID: 1, Status: status}}
			}
			if status == "pending" {
				if err := s.ScheduledActions().MarkExecuting(context.Background(), 1); err != nil {
					t.Fatal(err)
				}
				return
			}
			storetest.CheckDao5NotPending(t, s.ScheduledActions(), 1)
		})
	}
}
