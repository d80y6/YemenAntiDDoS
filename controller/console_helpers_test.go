package main

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func dao10StripJSComments(src string) string {
	var out strings.Builder
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			j := i + 1
			for j < len(src) && src[j] != c {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(src) {
				j = len(src) - 1
			}
			out.WriteString(src[i : j+1])
			i = j
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			if i < len(src) {
				out.WriteByte('\n')
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return out.String()
			}
			out.WriteByte(' ')
			i += end + 3
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
}

func dao10HasIdentifier(text, name string) bool {
	return regexp.MustCompile(`(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(name) + `($|[^A-Za-z0-9_])`).MatchString(text)
}

func dao10ObsoleteAnomalyClaim(text string) bool {
	if strings.Contains(text, "xdrop_anomaly_requires_drop") {
		return true
	}
	for _, sentence := range regexp.MustCompile(`[。．.！!？?；;]`).Split(strings.ToLower(text), -1) {
		if strings.Contains(sentence, "rate_limit") && (strings.Contains(sentence, "skip") || strings.Contains(sentence, "跳过")) {
			return true
		}
	}
	return false
}

func TestDao10_K5_CommentStripper(t *testing.T) {
	in := "{ key: 'tcp' },\n  // { key: 'gre' },\n  /* { key: 'esp' }, */ { key: 'a//b' }, { key: 'c/*d' },\n"
	got := map[string]bool{}
	for _, m := range regexp.MustCompile(`key:\s*'([^']+)'`).FindAllStringSubmatch(dao10StripJSComments(in), -1) {
		got[m[1]] = true
	}
	if want := map[string]bool{"tcp": true, "a//b": true, "c/*d": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("stripped keys=%v want %v", got, want)
	}
}

func TestDao10_K6_PredicateExamples(t *testing.T) {
	for _, text := range []string{
		"Anomaly decoders (bad_fragment / invalid) only support action=drop; combining them with rate_limit is skipped (skip_reason=xdrop_anomaly_requires_drop).",
		"Anomaly decoder（bad_fragment / invalid）只能配 drop，搭配 rate_limit 会被跳过。",
		"Anomaly decoders (bad_fragment / invalid) are drop-only — pairing them with rate_limit is skipped.",
	} {
		if !dao10ObsoleteAnomalyClaim(text) {
			t.Errorf("old sentence accepted: %s", text)
		}
	}
	for _, text := range []string{
		"Anomaly decoders (bad_fragment / invalid) use xDrop v3 anomaly-bit matching and support both drop and rate_limit; xDrop rejects IPv6 bad_fragment.",
		"异常类（bad_fragment / invalid）经 xDrop v3 异常位匹配，drop 与 rate_limit 均可；IPv6 bad_fragment 由 xDrop 拒绝。",
		"ip is skipped. Anomalies allow rate_limit.", "ip 会跳过。异常类可配 rate_limit。",
	} {
		if dao10ObsoleteAnomalyClaim(text) {
			t.Errorf("new sentence rejected: %s", text)
		}
	}
	if dao10HasIdentifier("tcp_ack", "tcp") || !dao10HasIdentifier("tcp / tcp_ack", "tcp") {
		t.Error("complete identifier boundary check failed")
	}
}
