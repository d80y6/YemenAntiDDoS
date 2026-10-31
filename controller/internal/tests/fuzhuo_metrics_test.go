package tests

import (
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestFuzhuo_Metrics_AllLabelsInitialized(t *testing.T) {
	s := NewMockStore()
	r := prometheus.NewRegistry()
	fzCheck(t, metrics.Register(r, s, dao4Tracker(s, nil)))
	families, err := r.Gather()
	fzCheck(t, err)
	want := map[string]bool{}
	for _, outcome := range []string{"dispatched", "detached_kept", "recounted_up", "skipped_inconsistent", "skipped_scheduled", "skipped_connector", "failed"} {
		want["bgp/"+outcome] = true
	}
	for _, outcome := range []string{"dispatched", "skipped_scheduled", "skipped_claimed", "failed"} {
		want["xdrop/"+outcome] = true
	}
	got := map[string]bool{}
	for _, family := range families {
		if family.GetName() != "xsight_startup_cleanup_total" {
			continue
		}
		for _, metric := range family.Metric {
			labels := map[string]string{}
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			got[labels["kind"]+"/"+labels["outcome"]] = true
		}
	}
	fzEqual(t, "preinitialized label set", got, want)
}
