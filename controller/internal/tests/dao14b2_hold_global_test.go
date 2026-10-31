package tests

import (
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"
)

func TestDao14b2_D4G(t *testing.T) {
	for _, name := range []string{"NoParamUsesGlobal", "ZeroOverridesGlobal", "ForceExpireUsesGlobal", "ForceExpireHoldZero", "GlobalReleaseAtDeadline"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := dao14b2Config(100)
				cfg.ManualExpireHoldSeconds = 60
				f := dao14b2New(t, cfg, nil)
				start := f.confirm(dao4Threshold(false))
				end := time.Now()
				var w *httptest.ResponseRecorder
				logs := dao14b2Capture(func() {
					switch name {
					case "NoParamUsesGlobal":
						w = f.expire("", "tracker")
					case "ZeroOverridesGlobal":
						w = f.expire("?hold_seconds=0", "tracker")
					case "ForceExpireHoldZero":
						if !f.tk.ForceExpireHold(1, 0) {
							t.Fatal("missing id 1")
						}
					default:
						if !f.tk.ForceExpire(1) {
							t.Fatal("missing id 1")
						}
					}
				})
				if name == "ZeroOverridesGlobal" || name == "ForceExpireHoldZero" {
					dao14b2AssertZeroPath(t, f, w, logs, start, end)
					dao14b2AssertReconfirm(t, f, 2, false)
					return
				}
				limit := 30
				if name == "GlobalReleaseAtDeadline" {
					limit = 70
				}
				first := -1
				for k := 0; k < limit; k++ {
					f.step(false, dao4Threshold(false))
					if k < 60 && f.count("confirmed", 0) != 1 {
						t.Errorf("global hold re-confirmed at tick %d", k)
						break
					}
					if first < 0 && f.count("confirmed", 2) > 0 {
						first = k
					}
				}
				if name == "GlobalReleaseAtDeadline" {
					if first != 63 || f.count("confirmed", 2) != 1 {
						t.Errorf("global release first tick=%d new confirmed=%d; want 63/1", first, f.count("confirmed", 2))
					}
				} else if first != -1 || f.count("confirmed", 0) != 1 {
					t.Error("global hold failed")
				}
			})
		})
	}
}
