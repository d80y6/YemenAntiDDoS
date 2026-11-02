package action

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func dao11aFunction(t *testing.T, path, name string) *ast.FuncDecl {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("%s: function %s not found", path, name)
	return nil
}

// Only inspect assignments directly in the requested block, by variable name.
func dao11aLiteral(t *testing.T, body *ast.BlockStmt, name string) *ast.CompositeLit {
	t.Helper()
	for _, stmt := range body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok {
			continue
		}
		for i, lhs := range assign.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Name == name && i < len(assign.Rhs) {
				if lit, ok := assign.Rhs[i].(*ast.CompositeLit); ok {
					return lit
				}
			}
		}
	}
	t.Fatalf("composite literal for %s not found", name)
	return nil
}

func dao11aString(t *testing.T, expr ast.Expr) string {
	t.Helper()
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		t.Fatalf("expected string literal, got %T", expr)
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func dao11aPairKeys(t *testing.T, pairs []string) map[string]bool {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatalf("odd replacement table length: %d", len(pairs))
	}
	keys := map[string]bool{}
	for i := 0; i < len(pairs); i += 2 {
		keys[pairs[i]] = true
	}
	return keys
}

func dao11aPositive(t *testing.T, label string, keys map[string]bool, known string) {
	t.Helper()
	if len(keys) == 0 || !keys[known] {
		t.Fatalf("%s: count=%d, missing positive member %q", label, len(keys), known)
	}
	t.Logf("%s: count=%d positive=%q", label, len(keys), known)
}

func dao11aEqual(t *testing.T, left, right map[string]bool) {
	t.Helper()
	if reflect.DeepEqual(left, right) {
		return
	}
	var leftOnly, rightOnly []string
	for key := range left {
		if !right[key] {
			leftOnly = append(leftOnly, key)
		}
	}
	for key := range right {
		if !left[key] {
			rightOnly = append(rightOnly, key)
		}
	}
	sort.Strings(leftOnly)
	sort.Strings(rightOnly)
	t.Errorf("set mismatch: left-only=%v right-only=%v", leftOnly, rightOnly)
}

func TestDao11a_Ga_TemplateVariables(t *testing.T) {
	supported := map[string]bool{}
	for name := range SupportedTemplateVars {
		supported["{"+name+"}"] = true
	}
	fn := dao11aFunction(t, "engine.go", "expandParams")
	lit := dao11aLiteral(t, fn.Body, "pairs")
	array, ok := lit.Type.(*ast.ArrayType)
	if !ok || array.Len != nil {
		t.Fatal("pairs must be a slice literal")
	}
	if elem, ok := array.Elt.(*ast.Ident); !ok || elem.Name != "string" {
		t.Fatal("pairs must be a []string literal")
	}
	if len(lit.Elts)%2 != 0 {
		t.Fatal("pairs literal has odd length")
	}
	base := map[string]bool{}
	for i := 0; i < len(lit.Elts); i += 2 {
		base[dao11aString(t, lit.Elts[i])] = true
	}
	flow := dao11aPairKeys(t, flowAnalysisReplacements(nil))
	dao11aPositive(t, "SupportedTemplateVars (braced)", supported, "{ip}")
	dao11aPositive(t, "expandParams.pairs", base, "{dst_ip}")
	dao11aPositive(t, "flowAnalysisReplacements(nil)", flow, "{top_src_ips}")
	for key := range flow {
		base[key] = true
	}
	dao11aEqual(t, supported, base)
	for name := range SupportedTemplateVars {
		placeholder := "{" + name + "}"
		if got := expandParams(placeholder, &store.Attack{}, "", "", nil); got == placeholder {
			t.Errorf("expandParams left supported placeholder %q unchanged", placeholder)
		}
	}
	t.Logf("black-box expansion checked %d supported placeholders", len(supported))
}

func TestDao11a_Gb_FlowVariablePrefixes(t *testing.T) {
	prefixes := map[string]bool{}
	for _, key := range flowVarPrefixes {
		prefixes[key] = true
	}
	replacements := dao11aPairKeys(t, flowAnalysisReplacements(nil))
	dao11aPositive(t, "flowVarPrefixes", prefixes, "{top_src_ips}")
	dao11aPositive(t, "flowAnalysisReplacements(nil)", replacements, "{top_src_ips}")
	dao11aEqual(t, prefixes, replacements)
}

func TestDao11a_Gc_PreconditionAttributes(t *testing.T) {
	fn := dao11aFunction(t, "engine.go", "evaluateStructuredPrecondition")
	attrs := map[string]bool{}
	for _, stmt := range fn.Body.List {
		sw, ok := stmt.(*ast.SwitchStmt)
		if !ok {
			continue
		}
		tag, ok := sw.Tag.(*ast.SelectorExpr)
		if !ok || tag.Sel.Name != "Attribute" {
			continue
		}
		if recv, ok := tag.X.(*ast.Ident); !ok || recv.Name != "p" {
			continue
		}
		// Direct case clauses only: nested p.Operator cases are not attributes.
		for _, stmt := range sw.Body.List {
			for _, expr := range stmt.(*ast.CaseClause).List {
				attrs[dao11aString(t, expr)] = true
			}
		}
	}
	api := dao11aFunction(t, "../api/responses.go", "replacePreconditions")
	var closure *ast.FuncLit
	for _, stmt := range api.Body.List {
		if ret, ok := stmt.(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
			closure, _ = ret.Results[0].(*ast.FuncLit)
		}
	}
	if closure == nil {
		t.Fatal("replacePreconditions return closure not found")
	}
	valid := map[string]bool{}
	for _, expr := range dao11aLiteral(t, closure.Body, "validAttrs").Elts {
		kv, ok := expr.(*ast.KeyValueExpr)
		if !ok {
			t.Fatalf("validAttrs entry is %T, not a key/value", expr)
		}
		valid[dao11aString(t, kv.Key)] = true
	}
	dao11aPositive(t, "evaluateStructuredPrecondition switch p.Attribute", attrs, "cidr")
	dao11aPositive(t, "replacePreconditions.validAttrs", valid, "cidr")
	dao11aEqual(t, attrs, valid)
}
