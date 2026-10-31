package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"testing"
)

func TestConsoleXDropRules(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "internal/action/xdrop.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var values []string
	declarations := 0
	ast.Inspect(file, func(n ast.Node) bool {
		d, ok := n.(*ast.GenDecl)
		if !ok || d.Tok != token.CONST {
			return true
		}
		for _, spec := range d.Specs {
			v := spec.(*ast.ValueSpec)
			for i, name := range v.Names {
				if name.Name != "xDropSyntheticFailedRuleIDPrefix" {
					continue
				}
				declarations++
				if i >= len(v.Values) {
					t.Fatal("backend constant has no literal")
				}
				literal, ok := v.Values[i].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatal("backend constant is not a string literal")
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				values = append(values, value)
			}
		}
		return false
	})
	if declarations != 1 || len(values) != 1 || values[0] == "" {
		t.Fatalf("backend declarations=%d values=%v; want exactly one nonempty literal", declarations, values)
	}
	raw, err := os.ReadFile("console/src/api/xdropRules.ts")
	if err != nil {
		t.Fatal(err)
	}
	source := dao10StripJSComments(string(raw))
	names := regexp.MustCompile(`\bconst\s+SYNTHETIC_RULE_PREFIX\b`).FindAllString(source, -1)
	matches := regexp.MustCompile(`(?m)^export const SYNTHETIC_RULE_PREFIX = '([^'\n]+)'\s*$`).FindAllStringSubmatch(source, -1)
	if len(names) != 1 || len(matches) != 1 {
		t.Fatalf("frontend declarations=%d literals=%d; want exactly one", len(names), len(matches))
	}
	if matches[0][1] != values[0] {
		t.Fatalf("SYNTHETIC_RULE_PREFIX=%q backend=%q", matches[0][1], values[0])
	}
	t.Logf("Go and console synthetic prefix agree: %q", values[0])
}
