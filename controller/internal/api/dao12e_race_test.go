package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/baseline"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
)

const dao12eNode, dao12ePrefix = "dao12e", "192.0.2.0/24"

func TestDao12e_G2_R6(t *testing.T)  { dao12eOverviewRace(t, "receives") }
func TestDao12e_G2_R6s(t *testing.T) { dao12eOverviewRace(t, "sends") }

func dao12eOverviewRace(t *testing.T, direction string) {
	t.Helper()
	rings := ring.New(ring.DefaultLimits())
	push := func() {
		dp := ring.DataPoint{Time: time.Now(), PPS: 100}
		if direction == "receives" {
			rings.PushPrefix(dao12eNode, dao12ePrefix, dp)
		} else {
			rings.PushSrcPrefix(dao12eNode, dao12ePrefix, dp)
		}
	}
	deps := Dependencies{Store: &dao11cStore{}, ProfileEngine: baseline.NewProfileEngine(rings, nil, nil)}
	w := dao12eRequestRace(t, "/api/stats/overview", "?direction="+direction, trafficOverview(deps), push)
	t.Run("Hit", func(t *testing.T) {
		var got struct {
			TotalPPS int64 `json:"total_pps"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusOK || got.TotalPPS != 100 {
			t.Fatalf("status=%d body=%s, want 200 and total_pps=100", w.Code, w.Body)
		}
	})
}

type dao12eProfiles struct{ store.DynDetectRepo }

func (dao12eProfiles) GetConfig(context.Context) (*store.DynDetectConfig, error) {
	return &store.DynDetectConfig{Enabled: true, StableWeeks: 1}, nil
}
func (dao12eProfiles) ListProfiles(_ context.Context, slot int) ([]store.PrefixProfile, error) {
	return []store.PrefixProfile{{
		NodeID: dao12eNode, Prefix: dao12ePrefix, SlotIndex: slot, SampleWeeks: 1,
	}}, nil
}

func TestDao12e_G2_R7(t *testing.T) {
	rings := ring.New(ring.DefaultLimits())
	profiles := baseline.NewProfileEngine(rings, dao12eProfiles{}, nil)
	if err := profiles.LoadFromDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Store: &dao11cStore{}, ProfileEngine: profiles}
	push := func() { rings.PushPrefix(dao12eNode, dao12ePrefix, ring.DataPoint{Time: time.Now(), PPS: 100}) }
	w := dao12eRequestRace(t, "/api/dynamic-detection/status", "", getDynDetectStatus(deps), push)
	t.Run("Hit", func(t *testing.T) {
		var got struct {
			Prefixes []struct {
				Prefix     string `json:"prefix"`
				CurrentPPS int64  `json:"current_pps"`
			} `json:"prefixes"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusOK || len(got.Prefixes) != 1 ||
			got.Prefixes[0].Prefix != dao12ePrefix || got.Prefixes[0].CurrentPPS != 100 {
			t.Fatalf("status=%d body=%s, want 200 and matching prefix current_pps=100", w.Code, w.Body)
		}
	})
}

func dao12eRequestRace(t *testing.T, route, query string, handler gin.HandlerFunc, push func()) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.GET(route, handler)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, route+query, nil)
	push()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Delay the write without creating a happens-before edge from the read.
		time.Sleep(50 * time.Millisecond)
		push()
	}()
	router.ServeHTTP(w, req)
	wg.Wait()
	return w
}
