package postgres

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func synBPSMigration(t *testing.T) string {
	t.Helper()
	var matches []string
	for _, m := range migrations {
		if strings.Contains(m, "ADD COLUMN tcp_syn_bps BIGINT DEFAULT 0") {
			matches = append(matches, m)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("SYN BPS ALTER count=%d, want 1", len(matches))
	}
	return matches[0]
}

func TestSynBPS_G2_Static(t *testing.T) {
	t.Run("migration", func(t *testing.T) {
		want := `DO $$ BEGIN ALTER TABLE ts_stats ADD COLUMN tcp_syn_bps BIGINT DEFAULT 0; EXCEPTION WHEN duplicate_column THEN NULL; END $$`
		if got := synBPSMigration(t); got != want {
			t.Fatalf("migration=%q, want %q", got, want)
		}
		frag, extras, syn := -1, -1, -1
		for i, m := range migrations {
			if strings.Contains(m, "ADD COLUMN frag_bps") {
				frag = i
			}
			if strings.Contains(m, "ADD COLUMN extra_decoder_bps") {
				extras = i
			}
			if m == want {
				syn = i
			}
			if strings.Contains(m, "CREATE TABLE IF NOT EXISTS ts_stats") && strings.Contains(m, "tcp_syn_bps") {
				t.Fatal("tcp_syn_bps must be added by ALTER, not CREATE TABLE")
			}
		}
		if frag < 0 || extras <= frag || syn != extras+1 {
			t.Fatalf("migration positions frag=%d extras=%d syn=%d", frag, extras, syn)
		}
		t.Logf("ALTER count=1 positions frag=%d extras=%d syn=%d", frag, extras, syn)
	})
	t.Run("cagg", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "postgres.go"))
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		start := strings.Index(src, "func (s *PGStore) ensureCagg(")
		end := strings.Index(src[start:], "\nfunc firstLine(")
		if start < 0 || end < 0 {
			t.Fatal("ensureCagg source boundaries not found")
		}
		if !strings.Contains(src[start:start+end], "avg(tcp_syn_bps)::BIGINT AS avg_tcp_syn_bps") {
			t.Fatal("ensureCagg missing avg(tcp_syn_bps)::BIGINT AS avg_tcp_syn_bps")
		}
	})
}
