package postgres

import (
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func feINET(input string) (string, error) {
	if net.ParseIP(input) == nil {
		return "", feError("22P02")
	}
	address, err := netip.ParseAddr(input)
	if err != nil {
		return "", err
	}
	if !strings.Contains(input, ":") {
		return address.String() + "/32", nil
	}
	return feIPv6Text(address.As16()) + "/128", nil
}

type feINETEntry struct {
	Input   string `json:"input"`
	GoValid bool   `json:"go_valid"`
	PGText  string `json:"pg_text"`
}

func feINETCorpus(t *testing.T) []feINETEntry {
	t.Helper()
	var entries []feINETEntry
	feRead(t, filepath.Join(feData, "inet-corpus.json"), &entries)
	return entries
}

func TestFEINET(t *testing.T) {
	entries := feINETCorpus(t)
	valid := 0
	if len(entries) != 43 {
		t.Fatalf("G-inet entries=%d; want 43", len(entries))
	}
	for _, entry := range entries {
		if (net.ParseIP(entry.Input) != nil) != entry.GoValid {
			t.Errorf("Go ParseIP %q: want valid=%t", entry.Input, entry.GoValid)
		}
		text, err := feINET(entry.Input)
		if entry.GoValid {
			valid++
			if err != nil || text != entry.PGText {
				t.Errorf("G-inet %q: %q %v; want %q", entry.Input, text, err, entry.PGText)
			}
		} else if err == nil {
			t.Errorf("G-inet %q: accepted rejected input", entry.Input)
		}
	}
	if valid != 28 {
		t.Fatalf("G-inet valid=%d; want 28", valid)
	}
	t.Log("G-inet entries=43 accepted=28 rejected=15")
}
