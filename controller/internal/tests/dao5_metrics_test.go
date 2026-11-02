package tests

import (
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestDao5_L1_AllOperationLabelsPresent(t *testing.T) {
	s := NewMockStore()
	r := prometheus.NewRegistry()
	if err := metrics.Register(r, s, dao4Tracker(s, nil)); err != nil {
		t.Fatal(err)
	}
	fs, err := r.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"attack_create": false, "attack_update_expired": false, "attack_update_evicted": false, "bgp_ann_state": false, "sched_mark_executing": false, "force_remove_override": false, "force_remove_mark_withdrawn": false, "xdrop_mark_withdrawn": false, "xdrop_mark_failed": false, "xdrop_schedule_finish": false, "xdrop_exec_log": false, "xdrop_claim": false}
	for _, f := range fs {
		if f.GetName() == "xsight_state_write_failures_total" {
			for _, m := range f.Metric {
				for _, l := range m.Label {
					if l.GetName() == "op" {
						if _, ok := want[l.GetValue()]; !ok {
							t.Errorf("unexpected op %q", l.GetValue())
						}
						want[l.GetValue()] = true
					}
				}
			}
		}
	}
	for op, present := range want {
		if !present {
			t.Errorf("operation label %s absent before any write in this fixture", op)
		}
	}
}
