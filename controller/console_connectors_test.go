package main

import (
	"os"
	"regexp"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/shared/decoder"
)

func consoleConnectorsScope(t *testing.T, lang string) {
	t.Helper()
	raw, err := os.ReadFile("console/src/i18n/" + lang + ".ts")
	if err != nil {
		t.Fatal(err)
	}
	entries := regexp.MustCompile(`(?m)^\s*decoderScopeBody:\s*'([^'\n]*)',`).FindAllStringSubmatch(string(raw), -1)
	if len(entries) != 1 {
		t.Fatalf("connectors.decoderScopeBody count=%d want 1", len(entries))
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

func TestConsoleConnectorsZhScope(t *testing.T) { consoleConnectorsScope(t, "zh") }
func TestConsoleConnectorsEnScope(t *testing.T) { consoleConnectorsScope(t, "en") }
