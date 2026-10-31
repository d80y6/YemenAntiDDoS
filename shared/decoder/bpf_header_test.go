package decoder

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// dao10MacroValue accepts only a plain decimal right-hand side (optionally
// followed by a comment); any expression is reported instead of being read
// by its numeric prefix.
func dao10MacroValue(rhs string) (int, error) {
	if i := strings.Index(rhs, "//"); i >= 0 {
		rhs = rhs[:i]
	}
	rhs = regexp.MustCompile(`/\*.*?\*/`).ReplaceAllString(rhs, " ")
	rhs = strings.TrimSpace(rhs)
	if !regexp.MustCompile(`^\d+$`).MatchString(rhs) {
		return 0, fmt.Errorf("unsupported macro value %q (want a single decimal integer)", rhs)
	}
	return strconv.Atoi(rhs)
}

func TestDao10_K1_MacroValueParser(t *testing.T) {
	for rhs, want := range map[string]int{"0": 0, "  12  // Ping of Death": 12, "\t16": 16, " 3 /* x */": 3} {
		if got, err := dao10MacroValue(rhs); err != nil || got != want {
			t.Errorf("dao10MacroValue(%q)=%d,%v want %d", rhs, got, err, want)
		}
	}
	for _, rhs := range []string{"0 + 1", "(5)", "", "1u", "0x1"} {
		if _, err := dao10MacroValue(rhs); err == nil {
			t.Errorf("dao10MacroValue(%q) accepted an expression", rhs)
		}
	}
}

func TestDao10_K1_BPFHeader(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../node/bpf/xsight.h"))
	if err != nil {
		t.Fatal(err)
	}
	macros := map[string][]int{}
	var maxValues []int
	for _, m := range regexp.MustCompile(`(?m)^[ \t]*#[ \t]*define[ \t]+(DECODER_\w+|MAX_DECODERS)\b(.*)$`).FindAllStringSubmatch(string(b), -1) {
		v, err := dao10MacroValue(m[2])
		if err != nil {
			t.Errorf("%s: %v", m[1], err)
			continue
		}
		if m[1] == "MAX_DECODERS" {
			maxValues = append(maxValues, v)
			continue
		}
		name := strings.TrimPrefix(m[1], "DECODER_")
		macros[name] = append(macros[name], v)
	}
	// The sole historical spelling exception in the frozen BPF header.
	exceptions := map[string]string{"fragment": "FRAG"}
	want := map[string]bool{}
	for i, name := range Names {
		if name == "" {
			continue
		}
		macro := strings.ToUpper(name)
		if alias, ok := exceptions[name]; ok {
			macro = alias
		}
		want[macro] = true
		if values := macros[macro]; len(values) != 1 || values[0] != i {
			t.Errorf("Names[%d]=%s: DECODER_%s values=%v, want exactly [%d]", i, name, macro, values, i)
		}
	}
	for macro := range macros {
		if !want[macro] {
			t.Errorf("orphan DECODER_%s", macro)
		}
	}
	if len(maxValues) != 1 || maxValues[0] != MaxDecoders {
		t.Errorf("MAX_DECODERS=%v, want exactly [%d]", maxValues, MaxDecoders)
	}
}
