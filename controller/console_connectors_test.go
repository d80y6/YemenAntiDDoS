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
	// Locale files mix styles: en.ts uses unquoted keys + single-quoted values,
	// ar.ts uses double-quoted keys + double-quoted values. Accept both.
	entries := regexp.MustCompile(`(?m)^\s*"?decoderScopeBody"?:\s*('([^'\n]*)'|"([^"\n]*)"),`).FindAllStringSubmatch(string(raw), -1)
	if len(entries) != 1 {
		t.Fatalf("connectors.decoderScopeBody count=%d want 1", len(entries))
	}
	body := entries[0][2]
	if body == "" {
		body = entries[0][3]
	}
	for _, name := range decoder.Names {
		if name != "" && action.IsXDropCompatibleDecoder(name) && !dao10HasIdentifier(body, name) {
			t.Errorf("missing complete decoder identifier %s", name)
		}
	}
	if dao10ObsoleteAnomalyClaim(body) {
		t.Error("obsolete anomaly/rate_limit skip claim")
	}
}

func TestConsoleConnectorsArScope(t *testing.T) { consoleConnectorsScope(t, "ar") }
func TestConsoleConnectorsEnScope(t *testing.T) { consoleConnectorsScope(t, "en") }
