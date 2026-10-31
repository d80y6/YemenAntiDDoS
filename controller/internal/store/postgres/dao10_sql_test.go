package postgres

import (
	"strings"
	"testing"
)

func TestDao10_K4_SQLFragments(t *testing.T) {
	// Freeze a46d88a's nine names only; new registry names do not change this oracle.
	names := []string{"tcp_ack", "tcp_rst", "tcp_fin", "gre", "esp", "igmp", "ip_other", "bad_fragment", "invalid"}
	normalize := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	cases := []struct{ name, got, want string }{
		{"cagg_1h_pps", caggExtraJSON(names, "1h", "pps"), `jsonb_strip_nulls(jsonb_build_object(
				'tcp_ack',      NULLIF(avg(total_tcp_ack_pps)::INT,      0),
				'tcp_rst',      NULLIF(avg(total_tcp_rst_pps)::INT,      0),
				'tcp_fin',      NULLIF(avg(total_tcp_fin_pps)::INT,      0),
				'gre',          NULLIF(avg(total_gre_pps)::INT,          0),
				'esp',          NULLIF(avg(total_esp_pps)::INT,          0),
				'igmp',         NULLIF(avg(total_igmp_pps)::INT,         0),
				'ip_other',     NULLIF(avg(total_ip_other_pps)::INT,     0),
				'bad_fragment', NULLIF(avg(total_bad_fragment_pps)::INT, 0),
				'invalid',      NULLIF(avg(total_invalid_pps)::INT,      0)
			))`},
		{"cagg_1h_bps", caggExtraJSON(names, "1h", "bps"), `jsonb_strip_nulls(jsonb_build_object(
				'tcp_ack',      NULLIF(avg(total_tcp_ack_bps)::BIGINT,      0),
				'tcp_rst',      NULLIF(avg(total_tcp_rst_bps)::BIGINT,      0),
				'tcp_fin',      NULLIF(avg(total_tcp_fin_bps)::BIGINT,      0),
				'gre',          NULLIF(avg(total_gre_bps)::BIGINT,          0),
				'esp',          NULLIF(avg(total_esp_bps)::BIGINT,          0),
				'igmp',         NULLIF(avg(total_igmp_bps)::BIGINT,         0),
				'ip_other',     NULLIF(avg(total_ip_other_bps)::BIGINT,     0),
				'bad_fragment', NULLIF(avg(total_bad_fragment_bps)::BIGINT, 0),
				'invalid',      NULLIF(avg(total_invalid_bps)::BIGINT,      0)
			))`},
		{"cagg_5min_pps", caggExtraJSON(names, "5min", "pps"), `jsonb_strip_nulls(jsonb_build_object(
				'tcp_ack',      NULLIF(sum(avg_tcp_ack_pps)::INT,      0),
				'tcp_rst',      NULLIF(sum(avg_tcp_rst_pps)::INT,      0),
				'tcp_fin',      NULLIF(sum(avg_tcp_fin_pps)::INT,      0),
				'gre',          NULLIF(sum(avg_gre_pps)::INT,          0),
				'esp',          NULLIF(sum(avg_esp_pps)::INT,          0),
				'igmp',         NULLIF(sum(avg_igmp_pps)::INT,         0),
				'ip_other',     NULLIF(sum(avg_ip_other_pps)::INT,     0),
				'bad_fragment', NULLIF(sum(avg_bad_fragment_pps)::INT, 0),
				'invalid',      NULLIF(sum(avg_invalid_pps)::INT,      0)
			))`},
		{"cagg_5min_bps", caggExtraJSON(names, "5min", "bps"), `jsonb_strip_nulls(jsonb_build_object(
				'tcp_ack',      NULLIF(sum(avg_tcp_ack_bps)::BIGINT,      0),
				'tcp_rst',      NULLIF(sum(avg_tcp_rst_bps)::BIGINT,      0),
				'tcp_fin',      NULLIF(sum(avg_tcp_fin_bps)::BIGINT,      0),
				'gre',          NULLIF(sum(avg_gre_bps)::BIGINT,          0),
				'esp',          NULLIF(sum(avg_esp_bps)::BIGINT,          0),
				'igmp',         NULLIF(sum(avg_igmp_bps)::BIGINT,         0),
				'ip_other',     NULLIF(sum(avg_ip_other_bps)::BIGINT,     0),
				'bad_fragment', NULLIF(sum(avg_bad_fragment_bps)::BIGINT, 0),
				'invalid',      NULLIF(sum(avg_invalid_bps)::BIGINT,      0)
			))`},
		{"cagg_inner_pps", caggExtraTotals(names, "pps"), `sum(avg_tcp_ack_pps)      AS total_tcp_ack_pps,
					   sum(avg_tcp_rst_pps)      AS total_tcp_rst_pps,
					   sum(avg_tcp_fin_pps)      AS total_tcp_fin_pps,
					   sum(avg_gre_pps)          AS total_gre_pps,
					   sum(avg_esp_pps)          AS total_esp_pps,
					   sum(avg_igmp_pps)         AS total_igmp_pps,
					   sum(avg_ip_other_pps)     AS total_ip_other_pps,
					   sum(avg_bad_fragment_pps) AS total_bad_fragment_pps,
					   sum(avg_invalid_pps)      AS total_invalid_pps`},
		{"cagg_inner_bps", caggExtraTotals(names, "bps"), `sum(avg_tcp_ack_bps)      AS total_tcp_ack_bps,
					   sum(avg_tcp_rst_bps)      AS total_tcp_rst_bps,
					   sum(avg_tcp_fin_bps)      AS total_tcp_fin_bps,
					   sum(avg_gre_bps)          AS total_gre_bps,
					   sum(avg_esp_bps)          AS total_esp_bps,
					   sum(avg_igmp_bps)         AS total_igmp_bps,
					   sum(avg_ip_other_bps)     AS total_ip_other_bps,
					   sum(avg_bad_fragment_bps) AS total_bad_fragment_bps,
					   sum(avg_invalid_bps)      AS total_invalid_bps`},
		{"raw_inner_pps", rawExtraTotals(names, "pps"), `sum(COALESCE((extra_decoder_pps->>'tcp_ack')::int, 0))      AS s_tcp_ack,
						   sum(COALESCE((extra_decoder_pps->>'tcp_rst')::int, 0))      AS s_tcp_rst,
						   sum(COALESCE((extra_decoder_pps->>'tcp_fin')::int, 0))      AS s_tcp_fin,
						   sum(COALESCE((extra_decoder_pps->>'gre')::int, 0))          AS s_gre,
						   sum(COALESCE((extra_decoder_pps->>'esp')::int, 0))          AS s_esp,
						   sum(COALESCE((extra_decoder_pps->>'igmp')::int, 0))         AS s_igmp,
						   sum(COALESCE((extra_decoder_pps->>'ip_other')::int, 0))     AS s_ip_other,
						   sum(COALESCE((extra_decoder_pps->>'bad_fragment')::int, 0)) AS s_bad_fragment,
						   sum(COALESCE((extra_decoder_pps->>'invalid')::int, 0))      AS s_invalid`},
		{"raw_inner_bps", rawExtraTotals(names, "bps"), `sum(COALESCE((extra_decoder_bps->>'tcp_ack')::bigint, 0))      AS s_tcp_ack_b,
						   sum(COALESCE((extra_decoder_bps->>'tcp_rst')::bigint, 0))      AS s_tcp_rst_b,
						   sum(COALESCE((extra_decoder_bps->>'tcp_fin')::bigint, 0))      AS s_tcp_fin_b,
						   sum(COALESCE((extra_decoder_bps->>'gre')::bigint, 0))          AS s_gre_b,
						   sum(COALESCE((extra_decoder_bps->>'esp')::bigint, 0))          AS s_esp_b,
						   sum(COALESCE((extra_decoder_bps->>'igmp')::bigint, 0))         AS s_igmp_b,
						   sum(COALESCE((extra_decoder_bps->>'ip_other')::bigint, 0))     AS s_ip_other_b,
						   sum(COALESCE((extra_decoder_bps->>'bad_fragment')::bigint, 0)) AS s_bad_fragment_b,
						   sum(COALESCE((extra_decoder_bps->>'invalid')::bigint, 0))      AS s_invalid_b`},
		{"raw_5s_pps", rawExtraJSON(names, "5s", "pps"), `jsonb_strip_nulls(jsonb_build_object(
					       'tcp_ack',      NULLIF(sum((extra_decoder_pps->>'tcp_ack')::int),      0),
					       'tcp_rst',      NULLIF(sum((extra_decoder_pps->>'tcp_rst')::int),      0),
					       'tcp_fin',      NULLIF(sum((extra_decoder_pps->>'tcp_fin')::int),      0),
					       'gre',          NULLIF(sum((extra_decoder_pps->>'gre')::int),          0),
					       'esp',          NULLIF(sum((extra_decoder_pps->>'esp')::int),          0),
					       'igmp',         NULLIF(sum((extra_decoder_pps->>'igmp')::int),         0),
					       'ip_other',     NULLIF(sum((extra_decoder_pps->>'ip_other')::int),     0),
					       'bad_fragment', NULLIF(sum((extra_decoder_pps->>'bad_fragment')::int), 0),
					       'invalid',      NULLIF(sum((extra_decoder_pps->>'invalid')::int),      0)
					   ))`},
		{"raw_5s_bps", rawExtraJSON(names, "5s", "bps"), `jsonb_strip_nulls(jsonb_build_object(
					       'tcp_ack',      NULLIF(sum((extra_decoder_bps->>'tcp_ack')::bigint),      0),
					       'tcp_rst',      NULLIF(sum((extra_decoder_bps->>'tcp_rst')::bigint),      0),
					       'tcp_fin',      NULLIF(sum((extra_decoder_bps->>'tcp_fin')::bigint),      0),
					       'gre',          NULLIF(sum((extra_decoder_bps->>'gre')::bigint),          0),
					       'esp',          NULLIF(sum((extra_decoder_bps->>'esp')::bigint),          0),
					       'igmp',         NULLIF(sum((extra_decoder_bps->>'igmp')::bigint),         0),
					       'ip_other',     NULLIF(sum((extra_decoder_bps->>'ip_other')::bigint),     0),
					       'bad_fragment', NULLIF(sum((extra_decoder_bps->>'bad_fragment')::bigint), 0),
					       'invalid',      NULLIF(sum((extra_decoder_bps->>'invalid')::bigint),      0)
					   ))`},
		{"raw_5min_1h_pps", rawExtraJSON(names, "5min", "pps"), `jsonb_strip_nulls(jsonb_build_object(
					       'tcp_ack',      NULLIF(avg(s_tcp_ack)::INT,      0),
					       'tcp_rst',      NULLIF(avg(s_tcp_rst)::INT,      0),
					       'tcp_fin',      NULLIF(avg(s_tcp_fin)::INT,      0),
					       'gre',          NULLIF(avg(s_gre)::INT,          0),
					       'esp',          NULLIF(avg(s_esp)::INT,          0),
					       'igmp',         NULLIF(avg(s_igmp)::INT,         0),
					       'ip_other',     NULLIF(avg(s_ip_other)::INT,     0),
					       'bad_fragment', NULLIF(avg(s_bad_fragment)::INT, 0),
					       'invalid',      NULLIF(avg(s_invalid)::INT,      0)
					   ))`},
		{"raw_5min_1h_bps", rawExtraJSON(names, "5min", "bps"), `jsonb_strip_nulls(jsonb_build_object(
					       'tcp_ack',      NULLIF(avg(s_tcp_ack_b)::BIGINT,      0),
					       'tcp_rst',      NULLIF(avg(s_tcp_rst_b)::BIGINT,      0),
					       'tcp_fin',      NULLIF(avg(s_tcp_fin_b)::BIGINT,      0),
					       'gre',          NULLIF(avg(s_gre_b)::BIGINT,          0),
					       'esp',          NULLIF(avg(s_esp_b)::BIGINT,          0),
					       'igmp',         NULLIF(avg(s_igmp_b)::BIGINT,         0),
					       'ip_other',     NULLIF(avg(s_ip_other_b)::BIGINT,     0),
					       'bad_fragment', NULLIF(avg(s_bad_fragment_b)::BIGINT, 0),
					       'invalid',      NULLIF(avg(s_invalid_b)::BIGINT,      0)
					   ))`},
		{"cagg_definition_pps", caggExtraColumns(names, "pps"), `avg(COALESCE((extra_decoder_pps->>'tcp_ack')::int, 0))::INT      AS avg_tcp_ack_pps,
			   avg(COALESCE((extra_decoder_pps->>'tcp_rst')::int, 0))::INT      AS avg_tcp_rst_pps,
			   avg(COALESCE((extra_decoder_pps->>'tcp_fin')::int, 0))::INT      AS avg_tcp_fin_pps,
			   avg(COALESCE((extra_decoder_pps->>'gre')::int, 0))::INT          AS avg_gre_pps,
			   avg(COALESCE((extra_decoder_pps->>'esp')::int, 0))::INT          AS avg_esp_pps,
			   avg(COALESCE((extra_decoder_pps->>'igmp')::int, 0))::INT         AS avg_igmp_pps,
			   avg(COALESCE((extra_decoder_pps->>'ip_other')::int, 0))::INT     AS avg_ip_other_pps,
			   avg(COALESCE((extra_decoder_pps->>'bad_fragment')::int, 0))::INT AS avg_bad_fragment_pps,
			   avg(COALESCE((extra_decoder_pps->>'invalid')::int, 0))::INT      AS avg_invalid_pps`},
		{"cagg_definition_bps", caggExtraColumns(names, "bps"), `avg(COALESCE((extra_decoder_bps->>'tcp_ack')::bigint, 0))::BIGINT      AS avg_tcp_ack_bps,
			   avg(COALESCE((extra_decoder_bps->>'tcp_rst')::bigint, 0))::BIGINT      AS avg_tcp_rst_bps,
			   avg(COALESCE((extra_decoder_bps->>'tcp_fin')::bigint, 0))::BIGINT      AS avg_tcp_fin_bps,
			   avg(COALESCE((extra_decoder_bps->>'gre')::bigint, 0))::BIGINT          AS avg_gre_bps,
			   avg(COALESCE((extra_decoder_bps->>'esp')::bigint, 0))::BIGINT          AS avg_esp_bps,
			   avg(COALESCE((extra_decoder_bps->>'igmp')::bigint, 0))::BIGINT         AS avg_igmp_bps,
			   avg(COALESCE((extra_decoder_bps->>'ip_other')::bigint, 0))::BIGINT     AS avg_ip_other_bps,
			   avg(COALESCE((extra_decoder_bps->>'bad_fragment')::bigint, 0))::BIGINT AS avg_bad_fragment_bps,
			   avg(COALESCE((extra_decoder_bps->>'invalid')::bigint, 0))::BIGINT      AS avg_invalid_bps`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if normalize(tc.got) != normalize(tc.want) {
				t.Errorf("SQL fragment differs from HEAD\ngot:  %s\nwant: %s", normalize(tc.got), normalize(tc.want))
			}
		})
	}
}

func TestDao10_K8_CaggDefinition(t *testing.T) {
	TestCaggV7_IncludesExtraDecoderAggregatesWithCoalesce(t)
}
