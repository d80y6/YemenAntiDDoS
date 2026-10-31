package decoder

import (
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Parse C integer expressions with precedence: !, &, &&, ||.
func dao12gEval(t *testing.T, expression string, flags int) int {
	t.Helper()
	tokens := regexp.MustCompile(`tcp_flags|0x[0-9a-fA-F]+|&&|\|\||[&!()]`).FindAllString(expression, -1)
	if strings.Join(tokens, "") != regexp.MustCompile(`\s+`).ReplaceAllString(expression, "") {
		t.Fatalf("unknown token in %q", expression)
	}
	tokens = append(tokens, "")
	at := 0
	truth := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	var parse func(int) int
	parse = func(min int) int {
		word := tokens[at]
		at++
		var value int
		switch word {
		case "!":
			value = truth(parse(4) == 0)
		case "(":
			value = parse(1)
			if tokens[at] != ")" {
				t.Fatalf("missing closing parenthesis in %q", expression)
			}
			at++
		case "tcp_flags":
			value = flags
		default:
			number, err := strconv.ParseInt(word, 0, 32)
			if err != nil || !strings.HasPrefix(word, "0x") {
				t.Fatalf("expected operand in %q, got %q", expression, word)
			}
			value = int(number)
		}
		for {
			op := tokens[at]
			precedence := map[string]int{"||": 1, "&&": 2, "&": 3}[op]
			if precedence < min {
				return value
			}
			at++
			right := parse(precedence + 1) // Always consume both operands.
			switch op {
			case "&":
				value &= right
			case "&&":
				value = truth(value != 0 && right != 0)
			case "||":
				value = truth(value != 0 || right != 0)
			}
		}
	}
	value := parse(1)
	if tokens[at] != "" {
		t.Fatalf("trailing expression in %q: %q", expression, tokens[at:])
	}
	return value
}

func TestDao12g_G2(t *testing.T) {
	var conditions []string
	var names []string
	extracted := t.Run("Extract", func(t *testing.T) {
		path := os.Getenv("XSIGHT_DAO12G_BPF_PATH")
		if path == "" {
			path = "../../node/bpf/xsight.c"
		}
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		macro := regexp.MustCompile(`(?ms)^#define DECODER_SWITCH\([^\n]*\n.*?^\} while \(0\)`).FindString(string(source))
		tcp := regexp.MustCompile(`(?s)case\s+IPPROTO_TCP:\s*(.*?)break;`).FindStringSubmatch(strings.ReplaceAll(macro, "\\\n", "\n"))
		if len(tcp) != 2 {
			t.Fatal("DECODER_SWITCH TCP segment not found")
		}
		writes := regexp.MustCompile(`^\s*__sync_fetch_and_add\(&\(counts\)\[(DECODER_\w+)\],\s*1\);\s*__sync_fetch_and_add\(&\(byte_counts\)\[(DECODER_\w+)\],\s*pkt_len\);\s*`)
		decoderName := func(body string) (string, string) {
			m := writes.FindStringSubmatch(body)
			if len(m) != 3 || m[1] != m[2] {
				t.Fatalf("counts/byte_counts writes missing or mismatched: %q", body)
			}
			name := map[string]string{"DECODER_TCP": "tcp", "DECODER_TCP_SYN": "tcp_syn",
				"DECODER_TCP_ACK": "tcp_ack", "DECODER_TCP_RST": "tcp_rst", "DECODER_TCP_FIN": "tcp_fin"}[m[1]]
			if name == "" {
				t.Fatalf("unknown decoder %q", m[1])
			}
			return name, body[len(m[0]):]
		}
		name, rest := decoderName(tcp[1])
		if name != "tcp" {
			t.Fatalf("unconditional decoder = %q, want tcp", name)
		}
		// The condition extends to the brace, not the first closing parenthesis.
		branch := regexp.MustCompile(`(?s)^\s*if\s*\(([^{}]+)\)\s*\{([^{}]*)\}\s*`)
		for strings.TrimSpace(rest) != "" {
			m := branch.FindStringSubmatch(rest)
			if len(m) != 3 {
				t.Fatalf("unconsumed TCP branch or token: %q", rest)
			}
			name, tail := decoderName(m[2])
			if strings.TrimSpace(tail) != "" {
				t.Fatalf("unconsumed branch body: %q", tail)
			}
			dao12gEval(t, m[1], 0)
			conditions, names = append(conditions, m[1]), append(names, name)
			rest = rest[len(m[0]):]
		}
		if len(conditions) < 4 {
			t.Fatalf("extracted %d TCP conditions, want at least 4", len(conditions))
		}
		t.Logf("extracted %d TCP conditions; counts and byte_counts agree", len(conditions))
	})
	if !extracted {
		t.Fatal("TCP extraction failed")
	}
	t.Run("Extract/SynPositive", func(t *testing.T) {
		for _, condition := range conditions {
			if regexp.MustCompile(`\b0x02\b`).MatchString(condition) &&
				regexp.MustCompile(`!\s*\(\s*\(tcp_flags\)\s*&\s*0x10\s*\)`).MatchString(condition) {
				return
			}
		}
		t.Error("no TCP condition combines SYN 0x02 with negated ACK 0x10")
	})
	t.Run("Parity", func(t *testing.T) {
		for flags := 0; flags < 256; flags++ {
			want := map[string]bool{"tcp": true}
			for i, condition := range conditions {
				if dao12gEval(t, condition, flags) != 0 {
					want[names[i]] = true
				}
			}
			result := parseResult{decoders: map[string]bool{}}
			dispatchDecoder(&result, 6, uint8(flags), false)
			if !reflect.DeepEqual(result.decoders, want) {
				t.Fatalf("flags=0x%02x: got %v, want %v", flags, result.decoders, want)
			}
		}
		t.Log("checked all 256 TCP flag values with fresh decoder sets including tcp")
	})
}
