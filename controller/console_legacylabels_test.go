package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestConsoleLegacyLabels(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "internal/action/engine.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var formats []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "legacyNoRowMessage" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "fmt" || sel.Sel.Name != "Sprintf" {
				return true
			}
			if len(call.Args) == 0 {
				t.Fatal("Sprintf has no format")
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("format must be a string literal")
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			formats = append(formats, value)
			return true
		})
	}
	if len(formats) != 1 {
		t.Fatalf("legacyNoRowMessage Sprintf count=%d; want 1", len(formats))
	}
	raw, err := os.ReadFile("console/src/i18n/en.ts")
	if err != nil {
		t.Fatal(err)
	}
	var sources []string
	err = filepath.WalkDir("console/src", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path == "console/src/i18n" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".vue" && filepath.Ext(path) != ".ts" {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sources = append(sources, regexp.MustCompile(`(?s)<!--.*?-->`).ReplaceAllString(
			dao10StripJSComments(string(content)), ""))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	section := regexp.MustCompile(`^  ["']?([A-Za-z_][A-Za-z_0-9]*)["']?: \{$`)
	property := regexp.MustCompile(`^    ["']?([A-Za-z_][A-Za-z_0-9]*)["']?:\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')`)
	values := map[string]string{}
	group := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if match := section.FindStringSubmatch(line); match != nil {
			group = match[1]
		}
		if match := property.FindStringSubmatch(line); match != nil {
			value := match[2][1 : len(match[2])-1]
			if strings.HasPrefix(match[2], `"`) {
				value, err = strconv.Unquote(match[2])
				if err != nil {
					t.Fatal(err)
				}
			}
			values[group+"."+match[1]] = value
		}
	}
	var literals []string
	for _, quoted := range regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`).FindAllString(string(raw), -1) {
		if strings.HasPrefix(quoted, `"`) {
			value, err := strconv.Unquote(quoted)
			if err != nil {
				t.Fatal(err)
			}
			literals = append(literals, value)
		} else {
			literals = append(literals, quoted[1:len(quoted)-1])
		}
	}
	for _, label := range []string{"Active Mitigations", "BGP Routing", "Force Withdraw", "Dismissed on upgrade", "Un-dismiss", "orphan", "dismissed orphans"} {
		if !strings.Contains(formats[0], label) {
			t.Errorf("backend format lacks %q", label)
		}
		found := false
		for _, literal := range literals {
			if literal == label || (label == "orphan" || label == "dismissed orphans") && strings.Contains(literal, label) {
				found = true
			}
		}
		t.Run("usage/"+label, func(t *testing.T) {
			var keys []string
			for key, value := range values {
				if value == label || (label == "orphan" || label == "dismissed orphans") && strings.Contains(value, label) {
					keys = append(keys, key)
				}
			}
			if len(keys) == 0 {
				t.Fatalf("no dictionary key for label %q", label)
			}
			for _, key := range keys {
				use := regexp.MustCompile(`(?:\$?t)\(\s*[^()]*['"]` + regexp.QuoteMeta(key) + `['"][^()]*\)`)
				for _, source := range sources {
					if use.MatchString(source) {
						return
					}
				}
			}
			t.Errorf("UI does not use label %q through t()/ $t(); candidate keys: %v", label, keys)
		})
		if !found {
			t.Errorf("en.ts lacks quoted UI label %q", label)
		}
	}
	t.Logf("legacyNoRowMessage: 1 format, 7 UI labels verified")
}
