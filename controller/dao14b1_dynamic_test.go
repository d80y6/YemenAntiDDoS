package main

import (
	"context"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine/baseline"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/threshold"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
)

type g4Dyn struct{ store.DynDetectRepo }

func (g4Dyn) GetConfig(context.Context) (*store.DynDetectConfig, error) {
	return &store.DynDetectConfig{Enabled: true, StableWeeks: 1, MinPPS: 1, MinBPS: 1}, nil
}
func (g4Dyn) ListProfiles(_ context.Context, slot int) ([]store.PrefixProfile, error) {
	return []store.PrefixProfile{{NodeID: "n1", Prefix: "192.0.2.0/24", SlotIndex: slot, ExpectedPPS: 1000, ExpectedBPS: 1 << 60, SampleWeeks: 4}}, nil
}

func g4DynRun(t *testing.T, pts []int64, window int) (sus []int) {
	synctest.Test(t, func(t *testing.T) {
		rs := ring.New(ring.Limits{MaxPointsPerIP: 120, MaxIPsPerPrefix: 100, MaxGlobalKeys: 1000})
		pe := baseline.NewProfileEngine(rs, g4Dyn{}, nil)
		if err := pe.LoadFromDB(context.Background()); err != nil {
			t.Fatal(err)
		}
		for _, p := range pts {
			time.Sleep(time.Second)
			if p > 0 {
				rs.PushPrefix("n1", "192.0.2.0/24", ring.DataPoint{Time: time.Unix(time.Now().Unix(), 0), PPS: p, BPS: 1})
			}
			for _, e := range dynamicBreaches([]string{"n1"}, []string{"192.0.2.0/24"}, rs, pe, window) {
				sus = append(sus, e.Sustained)
			}
		}
	})
	return sus
}

func TestDao14b1V04_Dynamic(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pts    []int64
		window int
		want   string
	}{
		{"Spike", []int64{3500, 3500, 0, 0}, 6, "[1 2 2 2]"},
		{"Sustained", []int64{3500, 3500, 3500, 3500}, 6, "[1 2 3 4]"},
		{"BadWindow/-4", []int64{3500, 3500}, -4, "[1 1]"},
		{"BadWindow/SustainWindow(-5,-5,120)", []int64{3500}, threshold.SustainWindow(-5, -5, 120), "[1]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sus := g4DynRun(t, tc.pts, tc.window)
			if fmt.Sprint(sus) != tc.want {
				t.Errorf("sustained per event=%v want %s", sus, tc.want)
			}
		})
	}
}
