package main

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/shared/decoder"
)

func TestConsoleDecoders(t *testing.T) {
	source, err := os.ReadFile("console/src/config/decoders.ts")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile(`(?s)export const DECODERS: Decoder\[\] = \[(.*?)\n\]`).FindAllStringSubmatch(string(source), -1)
	if len(blocks) != 1 {
		t.Fatalf("DECODERS lists=%d, want 1", len(blocks))
	}
	object := regexp.MustCompile(`^\s*\{([^{}]*)\}`)
	field := regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z_0-9]*)\s*:\s*'([^'\\]*)'\s*(,|$)`)
	body := strings.TrimSpace(blocks[0][1])
	entries := []map[string]string{}
	for body != "" {
		m := object.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("unrecognized DECODERS syntax: %q", body)
		}
		fields, entry := strings.TrimSpace(m[1]), map[string]string{}
		for fields != "" {
			f := field.FindStringSubmatch(fields)
			if f == nil {
				t.Fatalf("unrecognized field syntax: %q", fields)
			}
			if _, exists := entry[f[1]]; exists {
				t.Fatalf("duplicate field %s", f[1])
			}
			entry[f[1]] = f[2]
			fields = strings.TrimSpace(fields[len(f[0]):])
		}
		if len(entry) != 5 {
			t.Fatalf("entry fields=%d, want 5: %v", len(entry), entry)
		}
		for key := range entry {
			if key != "key" && key != "group" && key != "ppsField" && key != "bpsField" && key != "extraKey" {
				t.Fatalf("unknown entry field %s", key)
			}
		}
		entries = append(entries, entry)
		body = strings.TrimSpace(body[len(m[0]):])
		if body != "" {
			if !strings.HasPrefix(body, ",") {
				t.Fatalf("unrecognized separator: %q", body)
			}
			body = strings.TrimSpace(body[1:])
		}
	}
	if !t.Run("count", func(t *testing.T) {
		if len(entries) != 15 {
			t.Fatalf("parsed=%d want 15", len(entries))
		}
	}) {
		return
	}
	expected := []string{"total"}
	for _, name := range decoder.Names {
		if name != "" {
			expected = append(expected, name)
		}
	}
	keys := []string{}
	for _, entry := range entries {
		keys = append(keys, entry["key"])
	}
	sort.Strings(keys)
	sort.Strings(expected)
	if !t.Run("keys", func(t *testing.T) {
		if !reflect.DeepEqual(keys, expected) {
			t.Fatalf("keys=%v want %v", keys, expected)
		}
	}) {
		return
	}
	tags := map[string]bool{}
	typ := reflect.TypeOf(store.TimeseriesPoint{})
	for i := 0; i < typ.NumField(); i++ {
		tags[strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	t.Run("binding/tcp_syn/field", func(t *testing.T) {
		f, ok := reflect.TypeOf(store.TimeseriesPoint{}).FieldByName("TCPSynBPS")
		if !ok || f.Type.Kind() != reflect.Int64 || f.Tag.Get("json") != "tcp_syn_bps" {
			t.Errorf("TCPSynBPS must be int64 with json tag tcp_syn_bps and no omitempty")
		}
	})
	fixed := map[string][2]string{
		"tcp": {"tcp_pps", "tcp_bps"}, "tcp_syn": {"tcp_syn_pps", "tcp_syn_bps"},
		"udp": {"udp_pps", "udp_bps"}, "icmp": {"icmp_pps", "icmp_bps"}, "fragment": {"frag_pps", "frag_bps"},
	}
	fixedCount := 0
	for _, entry := range entries {
		key := entry["key"]
		pair, isFixed := fixed[key]
		extra := key
		if isFixed {
			fixedCount++
			extra = ""
		} else {
			pair = [2]string{"extra_decoder_pps", "extra_decoder_bps"}
		}
		if key == "total" {
			pair = [2]string{"pps", "bps"}
			extra = ""
		}
		t.Run("binding/"+key, func(t *testing.T) {
			if !tags[entry["ppsField"]] || !tags[entry["bpsField"]] {
				t.Errorf("fields must be TimeseriesPoint json tags")
			}
			if entry["ppsField"] != pair[0] || entry["bpsField"] != pair[1] || entry["extraKey"] != extra {
				t.Errorf("%s binding=%s/%s extra=%q, want %s/%s extra=%q", key,
					entry["ppsField"], entry["bpsField"], entry["extraKey"], pair[0], pair[1], extra)
			}
		})
	}
	if fixedCount != 5 {
		t.Fatalf("fixed=%d want 5", fixedCount)
	}
}
