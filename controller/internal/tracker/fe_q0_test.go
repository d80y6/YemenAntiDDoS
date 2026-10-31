package tracker

import (
	"encoding/json"
	"testing"
)

func TestFEQ0_G2_B12(t *testing.T) {
	for _, tc := range []struct {
		name, unit string
		value      int64
	}{{"Known", "pps", 123}, {"Zero", "pps", 0}, {"UnknownUnit", "", 123}} {
		t.Run(tc.name, func(t *testing.T) {
			tr := New(Config{}, nil, nil, nil, nil)
			key := attackKey{DstIP: "192.0.2.10", Direction: "receives", DecoderFamily: "udp"}
			tr.attacks[key] = &trackedAttack{Key: key, DBID: 1, State: StateActive, Prefix: "192.0.2.0/24", Unit: tc.unit, ThreshValue: tc.value}
			timer := tr.ActiveTimers()[1]
			if timer.Prefix != "192.0.2.0/24" {
				t.Fatalf("timer prefix=%q", timer.Prefix)
			}
			b, err := json.Marshal(timer)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(b, &fields); err != nil {
				t.Fatal(err)
			}
			if _, ok := fields["Prefix"]; ok {
				t.Fatal("internal Prefix serialized")
			}
			if _, ok := fields["prefix"]; ok {
				t.Fatal("internal prefix serialized")
			}
			value, hasValue := fields["threshold_value"]
			unit, hasUnit := fields["threshold_unit"]
			if tc.unit == "" {
				if hasValue || hasUnit {
					t.Fatalf("unknown threshold keys must be absent: %s", b)
				}
				return
			}
			if !hasValue || !hasUnit {
				t.Fatalf("known threshold keys missing: %s", b)
			}
			var gotValue int64
			var gotUnit string
			if err := json.Unmarshal(value, &gotValue); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(unit, &gotUnit); err != nil {
				t.Fatal(err)
			}
			if gotValue != tc.value || gotUnit != tc.unit {
				t.Fatalf("threshold=(%d,%q) want=(%d,%q)", gotValue, gotUnit, tc.value, tc.unit)
			}
			*timer.ThresholdValue = 999
			if *tr.ActiveTimers()[1].ThresholdValue != tc.value {
				t.Fatal("threshold pointer aliases tracker state")
			}
		})
	}
}
