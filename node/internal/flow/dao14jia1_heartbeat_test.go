package flow

import (
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestDao14jia1_G7a(t *testing.T) {
	t.Run("Shape", func(t *testing.T) {
		a := newTestAggregator(nil)
		m := a.HeartbeatAt(123, "n1", "flow", 1)
		if m.NodeId != "n1" || m.InterfaceName != "flow" || m.Timestamp != 123 || m.UpstreamSampleRate != 1 || m.LocalSampleRate != 1 {
			t.Fatalf("identity=%+v", m)
		}
		if m.GlobalStats != nil || len(m.IpStats)+len(m.PrefixStats)+len(m.SrcIpStats)+len(m.SrcPrefixStats)+len(m.TopFlows) != 0 {
			t.Fatalf("heartbeat has data payload: %+v", m)
		}
		if m.Health == nil || m.SamplingMetrics == nil {
			t.Fatal("heartbeat must contain health and metrics")
		}
	})
	t.Run("HealthJSON", func(t *testing.T) {
		a := newTestAggregator(nil)
		fresh := &Source{DeviceIP: netip.MustParseAddr("192.0.2.1")}
		old := &Source{DeviceIP: netip.MustParseAddr("192.0.2.2")}
		fresh.LastSeenAt.Store(time.Now().Unix())
		old.LastSeenAt.Store(time.Now().Unix() - 120)
		a.SetListeners([]*Listener{makeTestListener(map[string]*Source{"192.0.2.1": fresh, "192.0.2.2": old})})
		m := a.HeartbeatAt(123, "n1", "flow", 1)
		if m.Health == nil || !strings.HasPrefix(m.Health.Message, "{") {
			t.Fatal("health JSON missing")
		}
		var p struct {
			Sources []struct {
				DeviceIP string `json:"device_ip"`
				Active   bool   `json:"active"`
			} `json:"sources"`
			Listeners []json.RawMessage `json:"listeners"`
		}
		if err := json.Unmarshal([]byte(m.Health.Message), &p); err != nil {
			t.Fatal(err)
		}
		if len(p.Sources) != 2 || len(p.Listeners) != 1 {
			t.Fatalf("health=%s", m.Health.Message)
		}
		for _, s := range p.Sources {
			if s.Active != (s.DeviceIP == "192.0.2.1") {
				t.Errorf("active=%+v", s)
			}
		}
	})
	t.Run("DoesNotConsume", func(t *testing.T) {
		a := newTestAggregator([]string{"192.0.2.0/24"})
		a.Add(FlowRecord{SrcIP: net.ParseIP("198.51.100.1"), DstIP: net.ParseIP("192.0.2.1"), Protocol: 17, Packets: 10, Bytes: 600}, &Source{SampleMode: "none"})
		// Read the actual bucket timestamp to avoid an Add/clock-boundary race.
		a.mu.Lock()
		var ts int64
		for k := range a.buckets {
			ts = k
		}
		a.mu.Unlock()
		a.HeartbeatAt(ts, "n1", "flow", 1)
		m := a.FlushAt(ts, "n1", "flow", 1)
		if m == nil || m.GetGlobalStats().GetMatchedPkts() != 10 || len(m.TopFlows) == 0 {
			t.Fatalf("heartbeat consumed flow data: %v", m)
		}
	})
}
