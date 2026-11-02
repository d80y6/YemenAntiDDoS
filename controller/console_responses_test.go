package main

import (
	"os"
	"regexp"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/shared/decoder"
)

func consoleResponsesScope(t *testing.T, lang string) {
	t.Helper()
	raw, err := os.ReadFile("console/src/i18n/" + lang + ".ts")
	if err != nil {
		t.Fatal(err)
	}
	entries := regexp.MustCompile(`(?m)^\s*xdropDecoderScopeBody:\s*'([^'\n]*)',`).FindAllStringSubmatch(string(raw), -1)
	if len(entries) != 1 {
		t.Fatalf("responses.xdropDecoderScopeBody count=%d want 1", len(entries))
	}
	for _, name := range decoder.Names {
		if name != "" && action.IsXDropCompatibleDecoder(name) && !dao10HasIdentifier(entries[0][1], name) {
			t.Errorf("missing complete decoder identifier %s", name)
		}
	}
	if dao10ObsoleteAnomalyClaim(entries[0][1]) {
		t.Error("obsolete anomaly/rate_limit skip claim")
	}
}

func TestConsoleResponsesZhScope(t *testing.T) { consoleResponsesScope(t, "zh") }
func TestConsoleResponsesEnScope(t *testing.T) { consoleResponsesScope(t, "en") }
