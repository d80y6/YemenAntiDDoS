package decoder

import (
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// This is a text contract, not BPF execution. TCP flag subconditions and the
// bad_fragment/invalid branches are outside G-d's protocol/fragment scope.
func TestDao11a_Gd_DecoderSwitch(t *testing.T) {
	c, err := os.ReadFile("../../node/bpf/xsight.c")
	if err != nil {
		t.Fatal(err)
	}
	h, err := os.ReadFile("../../node/bpf/xsight.h")
	if err != nil {
		t.Fatal(err)
	}
	macro := regexp.MustCompile(`(?ms)^#define DECODER_SWITCH\([^\n]*\n.*?^\} while \(0\)`).FindString(string(c))
	if macro == "" {
		t.Fatal("DECODER_SWITCH macro not found")
	}
	macro = strings.ReplaceAll(macro, "\\\n", "\n")
	defs := map[string]int{}
	for _, match := range regexp.MustCompile(`(?m)^#define\s+((?:IPPROTO|DECODER)_\w+)\s+(\d+)\b`).FindAllStringSubmatch(string(h), -1) {
		value, err := strconv.Atoi(match[2])
		if err != nil {
			t.Fatal(err)
		}
		defs[match[1]] = value
	}
	if len(defs) == 0 || defs["IPPROTO_GRE"] != 47 {
		t.Fatal("xsight.h definitions missing positive IPPROTO_GRE=47")
	}
	// These three protocol numbers come from the untracked vmlinux.h, not xsight.h.
	for name, value := range map[string]int{"IPPROTO_TCP": 6, "IPPROTO_UDP": 17, "IPPROTO_ICMP": 1} {
		if _, exists := defs[name]; !exists {
			defs[name] = value
		}
	}
	counts := regexp.MustCompile(`\(counts\)\[(DECODER_\w+)\]`)
	bytes := regexp.MustCompile(`\(byte_counts\)\[(DECODER_\w+)\]`)
	decoderName := func(body string) string {
		// Only the unconditional main write; TCP flag branches follow the first if.
		body = strings.SplitN(body, "if (", 2)[0]
		cm, bm := counts.FindAllStringSubmatch(body, -1), bytes.FindAllStringSubmatch(body, -1)
		if len(cm) != 1 || len(bm) != 1 {
			t.Fatalf("expected one counts and one byte_counts main write: %q", body)
		}
		if cm[0][1] != bm[0][1] {
			t.Fatalf("DECODER_SWITCH counts/byte_counts mismatch: %s != %s", cm[0][1], bm[0][1])
		}
		index, ok := defs[cm[0][1]]
		if !ok || index < 0 || index >= len(Names) || Names[index] == "" {
			t.Fatalf("unregistered decoder constant %s", cm[0][1])
		}
		return Names[index]
	}
	protocols := map[int]string{}
	defaultName := ""
	branches := regexp.MustCompile(`(?s)((?:case\s+IPPROTO_\w+:\s*)+|default:)(.*?)break;`).FindAllStringSubmatch(macro, -1)
	for _, branch := range branches {
		name := decoderName(branch[2])
		if branch[1] == "default:" {
			defaultName = name
			continue
		}
		for _, label := range regexp.MustCompile(`case\s+(IPPROTO_\w+):`).FindAllStringSubmatch(branch[1], -1) {
			proto, ok := defs[label[1]]
			if !ok || proto < 0 || proto > 255 {
				t.Fatalf("missing/invalid protocol definition %s", label[1])
			}
			if _, exists := protocols[proto]; exists {
				t.Fatalf("duplicate protocol case %d", proto)
			}
			protocols[proto] = name
		}
	}
	if len(protocols) == 0 || protocols[6] != "tcp" || defaultName == "" {
		t.Fatalf("missing macro mapping/positive: count=%d TCP=%q default=%q", len(protocols), protocols[6], defaultName)
	}
	t.Logf("DECODER_SWITCH: protocol cases=%d positive=IPPROTO_TCP(6)->%s default=%s", len(protocols), protocols[6], defaultName)
	fragment := regexp.MustCompile(`(?s)if\s*\(is_frag\)\s*\{([^}]+)\}`).FindStringSubmatch(macro)
	if len(fragment) != 2 {
		t.Fatal("is_frag branch not found")
	}
	fragmentName := decoderName(fragment[1])
	if fragmentName != "fragment" {
		t.Fatalf("is_frag positive: got %q, want fragment", fragmentName)
	}
	t.Logf("fragment mapping: count=1 positive=is_frag->%s; counts/byte_counts agree", fragmentName)
	for proto := 0; proto < 256; proto++ {
		for _, fragmented := range []bool{false, true} {
			name, ok := protocols[proto]
			if !ok {
				name = defaultName
			}
			want := map[string]bool{name: true}
			if fragmented {
				want[fragmentName] = true
			}
			result := parseResult{decoders: map[string]bool{}}
			dispatchDecoder(&result, uint8(proto), 0, fragmented)
			if !reflect.DeepEqual(result.decoders, want) {
				t.Errorf("proto=%d fragmented=%t: got %v want %v", proto, fragmented, result.decoders, want)
			}
		}
	}
	t.Log("dispatchDecoder: checked 256 protocols x 2 fragment states = 512 fresh results, TCP flags=0")
}
