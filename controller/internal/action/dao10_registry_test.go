package action

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/shared/decoder"
)

func TestDao10_K2_XDropRegistry(t *testing.T) {
	bits := map[int]string{}
	names := append([]string{"ip"}, decoder.Names[:]...)
	for _, name := range names {
		if name == "" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			class := decoder.GetDispatchClass(name)
			compatible := IsXDropCompatibleDecoder(name)
			if compatible != (class != decoder.Unsupported) {
				t.Errorf("compatible=%v, dispatch class=%v", compatible, class)
			}
			if isAnomalyDecoder(name) != (class == decoder.Anomaly) {
				t.Errorf("anomaly classification differs from registry")
			}
			bit := xdropAnomalyBit(name)
			if (bit != 0) != (class == decoder.Anomaly) {
				t.Errorf("anomaly bit=%d, class=%v", bit, class)
			}
			if bit != 0 {
				if previous, exists := bits[bit]; exists {
					t.Errorf("anomaly bit %d shared by %s and %s", bit, previous, name)
				}
				bits[bit] = name
			}
			if _, exists := xdropDecoderSpec[name]; exists != compatible {
				t.Errorf("spec exists=%v, compatible=%v", exists, compatible)
			}
		})
	}
	wantKeys, gotKeys := map[string]bool{}, map[string]bool{}
	for name, spec := range xdropDecoderSpec {
		if spec.TCPFlagsAll != 0 {
			wantKeys[name] = true
		}
	}
	for name, pattern := range tcpFlagDecoderMap {
		gotKeys[name] = true
		all, none := 0, 0
		for _, part := range strings.Split(pattern, ",") {
			flag := strings.TrimPrefix(part, "!")
			bit, exists := map[string]int{"SYN": 2, "ACK": 16, "RST": 4, "FIN": 1}[flag]
			if !exists {
				t.Fatalf("%s: unknown flag %q", name, part)
			}
			if strings.HasPrefix(part, "!") {
				none |= bit
			} else {
				all |= bit
			}
		}
		spec := xdropDecoderSpec[name]
		if all != int(spec.TCPFlagsAll) || none != int(spec.TCPFlagsNone) {
			t.Errorf("%s pattern=%q bits=(%d,%d), spec=(%d,%d)", name, pattern, all, none, spec.TCPFlagsAll, spec.TCPFlagsNone)
		}
	}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Errorf("flag map keys=%v, flagged spec keys=%v", gotKeys, wantKeys)
	}
}

func TestDao10_K2b_XDropBodyDecisions(t *testing.T) {
	// Freeze HEAD's two stages separately: finalize pins fragment/icmp and can
	// otherwise conceal a changed specialize exception (M12).
	want := map[string]struct{ intermediate, final4, final6 string }{
		"tcp":          {`{}`, `{"protocol":"tcp"}`, `{"protocol":"tcp"}`},
		"tcp_syn":      {`{}`, `{"protocol":"tcp"}`, `{"protocol":"tcp"}`},
		"tcp_ack":      {`{}`, `{"protocol":"tcp"}`, `{"protocol":"tcp"}`},
		"tcp_rst":      {`{}`, `{"protocol":"tcp"}`, `{"protocol":"tcp"}`},
		"tcp_fin":      {`{}`, `{"protocol":"tcp"}`, `{"protocol":"tcp"}`},
		"udp":          {`{}`, `{"protocol":"udp"}`, `{"protocol":"udp"}`},
		"icmp":         {`{}`, `{"protocol":"icmp"}`, `{"protocol":"icmpv6"}`},
		"fragment":     {`{}`, `{"protocol":"all","fragment":"frag"}`, `{"protocol":"all"}`},
		"gre":          {`{"protocol":"gre"}`, `{"protocol":"gre"}`, `{"protocol":"gre"}`},
		"esp":          {`{"protocol":"esp"}`, `{"protocol":"esp"}`, `{"protocol":"esp"}`},
		"igmp":         {`{"protocol":"igmp"}`, `{"protocol":"igmp"}`, `{"protocol":"igmp"}`},
		"bad_fragment": {`{"match_anomaly":1}`, `{"match_anomaly":1}`, `{"match_anomaly":1}`},
		"invalid":      {`{"match_anomaly":2}`, `{"match_anomaly":2}`, `{"match_anomaly":2}`},
	}
	registered, keys := map[string]bool{}, map[string]bool{}
	for _, name := range decoder.Names {
		if name != "" && IsXDropCompatibleDecoder(name) {
			registered[name] = true
		}
	}
	for name := range want {
		keys[name] = true
	}
	if !reflect.DeepEqual(keys, registered) {
		t.Errorf("explicit body decisions=%v, compatible registry=%v", keys, registered)
	}
	for name, row := range want {
		for _, family := range []struct{ name, dst, final string }{
			{"v4", "192.0.2.1", row.final4}, {"v6", "2001:db8::1", row.final6},
		} {
			t.Run(name+"/"+family.name, func(t *testing.T) {
				attack := &store.Attack{DecoderFamily: name, DstIP: family.dst}
				body := specializeXDropDecoderBody([]byte(`{}`), attack)
				t.Run("intermediate", func(t *testing.T) { dao10BodyEqual(t, body, row.intermediate) })
				body, _ = finalizeXDropV3Body(body, attack, "dao10")
				t.Run("final", func(t *testing.T) { dao10BodyEqual(t, body, family.final) })
			})
		}
	}
}

func dao10BodyEqual(t *testing.T, body []byte, expected string) {
	t.Helper()
	var got, want map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		t.Fatal(err)
	}
	// Include absence: no ports, textual/numeric flag fields, unexpected anomaly
	// bits or fragment predicates may be silently added to the minimal body.
	delete(got, "claim_ref")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("body=%s, want=%s", body, expected)
	}
}
