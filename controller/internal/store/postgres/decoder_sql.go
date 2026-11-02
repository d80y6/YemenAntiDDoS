package postgres

import (
	"strings"

	"github.com/d80y6/YemenDDoS/shared/decoder"
)

func extraDecoderNames() []string {
	var names []string
	for _, name := range decoder.Names[decoder.StandardCount:] {
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

// decoderSQL preserves registry order; templates are fixed at the query sites.
func decoderSQL(names []string, template string) string {
	items := make([]string, 0, len(names))
	for _, name := range names {
		items = append(items, strings.ReplaceAll(template, "{name}", name))
	}
	return strings.Join(items, ", ")
}

func decoderSQLCast(unit string) string {
	if unit == "bps" {
		return "BIGINT"
	}
	return "INT"
}

func caggExtraJSON(names []string, resolution, unit string) string {
	expr := "sum(avg_{name}_" + unit + ")"
	if resolution == "1h" {
		expr = "avg(total_{name}_" + unit + ")"
	}
	return "jsonb_strip_nulls(jsonb_build_object( " + decoderSQL(names, "'{name}', NULLIF("+expr+"::"+decoderSQLCast(unit)+", 0)") + " ))"
}

func caggExtraTotals(names []string, unit string) string {
	return decoderSQL(names, "sum(avg_{name}_"+unit+") AS total_{name}_"+unit)
}

func rawExtraJSON(names []string, resolution, unit string) string {
	suffix := map[string]string{"pps": "", "bps": "_b"}[unit]
	expr := "avg(s_{name}" + suffix + ")::" + decoderSQLCast(unit)
	if resolution == "5s" {
		expr = "sum((extra_decoder_" + unit + "->>'{name}')::" + strings.ToLower(decoderSQLCast(unit)) + ")"
	}
	return "jsonb_strip_nulls(jsonb_build_object( " + decoderSQL(names, "'{name}', NULLIF("+expr+", 0)") + " ))"
}

func rawExtraTotals(names []string, unit string) string {
	suffix := map[string]string{"pps": "", "bps": "_b"}[unit]
	return decoderSQL(names, "sum(COALESCE((extra_decoder_"+unit+"->>'{name}')::"+strings.ToLower(decoderSQLCast(unit))+", 0)) AS s_{name}"+suffix)
}

func caggExtraColumns(names []string, unit string) string {
	cast := decoderSQLCast(unit)
	return decoderSQL(names, "avg(COALESCE((extra_decoder_"+unit+"->>'{name}')::"+strings.ToLower(cast)+", 0))::"+cast+" AS avg_{name}_"+unit)
}

func caggExtraColumnNames(names []string) []string {
	var columns []string
	for _, unit := range []string{"pps", "bps"} {
		for _, name := range names {
			columns = append(columns, "avg_"+name+"_"+unit)
		}
	}
	return columns
}
