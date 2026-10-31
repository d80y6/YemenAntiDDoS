package postgres

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func TestDao13e_G2_DuplicateSQL(t *testing.T) {
	tree, err := parser.ParseFile(token.NewFileSet(), "template.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var inserts []string
	for _, decl := range tree.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Duplicate" || fn.Recv == nil {
			continue
		}
		receiver, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		id, ok := receiver.X.(*ast.Ident)
		if !ok || id.Name != "templateRepo" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if ok && lit.Kind == token.STRING {
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(s, "INSERT INTO threshold_templates") {
					inserts = append(inserts, s)
				}
			}
			return true
		})
	}
	if len(inserts) != 1 {
		t.Fatalf("template insert count=%d want=1", len(inserts))
	}
	m := regexp.MustCompile(`(?is)INSERT INTO threshold_templates\s*\(([^)]+)\)\s*SELECT\s+(.+?)\s+FROM`).FindStringSubmatch(inserts[0])
	if len(m) != 3 {
		t.Fatalf("unrecognized INSERT SELECT: %q", inserts[0])
	}
	for i, name := range []string{"InsertColumns", "SelectColumns"} {
		t.Run(name, func(t *testing.T) {
			if !regexp.MustCompile(`\bresponse_id\b`).MatchString(m[i+1]) {
				t.Errorf("%s lacks response_id: %q", name, m[i+1])
			}
		})
	}
}

func dao13ePGCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDao13e_E1(t *testing.T) {
	s := newPostgresContractBackend(t).Store()
	ctx := context.Background()
	r1, err := s.Responses().Create(ctx, &store.Response{Name: "E1 default", Enabled: true})
	dao13ePGCheck(t, err)
	r2, err := s.Responses().Create(ctx, &store.Response{Name: "E1 override", Enabled: true})
	dao13ePGCheck(t, err)
	source, err := s.ThresholdTemplates().Create(ctx, &store.ThresholdTemplate{Name: "E1 source", Description: "copy contract", ResponseID: &r1})
	dao13ePGCheck(t, err)
	for i, row := range []store.Threshold{
		{Direction: "receives", Decoder: "udp", Value: 100, Enabled: true},
		{Direction: "receives", Decoder: "tcp_syn", Value: 200, ResponseID: &r2, Enabled: false},
		{Direction: "sends", Decoder: "ip", Value: 300, Enabled: true},
	} {
		row.TemplateID, row.Domain, row.Unit, row.Comparison, row.Inheritable = &source, "internal_ip", "pps", "over", i != 1
		_, err := s.Thresholds().Create(ctx, &row)
		dao13ePGCheck(t, err)
	}
	_, err = s.Prefixes().Create(ctx, &store.WatchPrefix{Prefix: "192.0.2.0/24", Name: "source binding", Enabled: true, ThresholdTemplateID: &source})
	dao13ePGCheck(t, err)
	beforeTemplate, err := s.ThresholdTemplates().Get(ctx, source)
	dao13ePGCheck(t, err)
	beforeRules, err := s.ThresholdTemplates().ListRules(ctx, source)
	dao13ePGCheck(t, err)
	copyID, err := s.ThresholdTemplates().Duplicate(ctx, source, "E1 copy")
	dao13ePGCheck(t, err)
	copyTemplate, err := s.ThresholdTemplates().Get(ctx, copyID)
	dao13ePGCheck(t, err)
	t.Run("DefaultResponse", func(t *testing.T) {
		if copyTemplate.ResponseID == nil || *copyTemplate.ResponseID != r1 {
			t.Errorf("copy default=%v want=%d", copyTemplate.ResponseID, r1)
		}
		if copyTemplate.Name != "E1 copy" || copyTemplate.Description != beforeTemplate.Description {
			t.Errorf("copy metadata=%+v", copyTemplate)
		}
	})
	copies, err := s.ThresholdTemplates().ListRules(ctx, copyID)
	dao13ePGCheck(t, err)
	t.Run("Rules", func(t *testing.T) {
		if len(copies) != 3 || len(beforeRules) != 3 {
			t.Fatalf("source=%+v copy=%+v", beforeRules, copies)
		}
		byDecoder := map[string]store.Threshold{}
		for _, row := range copies {
			byDecoder[row.Decoder] = row
		}
		for _, sourceRow := range beforeRules {
			row := byDecoder[sourceRow.Decoder]
			if row.TemplateID == nil || *row.TemplateID != copyID || row.PrefixID != nil {
				t.Errorf("copied rule ownership=%+v", row)
			}
			row.ID, row.TemplateID, row.CreatedAt = sourceRow.ID, sourceRow.TemplateID, sourceRow.CreatedAt
			if !reflect.DeepEqual(row, sourceRow) {
				t.Errorf("copy rule=%+v source=%+v", row, sourceRow)
			}
		}
	})
	t.Run("SourceUnchanged", func(t *testing.T) {
		afterTemplate, err := s.ThresholdTemplates().Get(ctx, source)
		dao13ePGCheck(t, err)
		afterRules, err := s.ThresholdTemplates().ListRules(ctx, source)
		dao13ePGCheck(t, err)
		if !reflect.DeepEqual(afterTemplate, beforeTemplate) || !reflect.DeepEqual(afterRules, beforeRules) {
			t.Errorf("source changed: template=%+v rules=%+v", afterTemplate, afterRules)
		}
	})
	t.Run("NoPrefixBindings", func(t *testing.T) {
		rows, err := s.Prefixes().List(ctx)
		dao13ePGCheck(t, err)
		for _, row := range rows {
			if row.ThresholdTemplateID != nil && *row.ThresholdTemplateID == copyID {
				t.Errorf("copy has prefix binding: %+v", row)
			}
		}
	})
	t.Run("NullDefault", func(t *testing.T) {
		id, err := s.ThresholdTemplates().Create(ctx, &store.ThresholdTemplate{Name: "E1 null"})
		dao13ePGCheck(t, err)
		copyID, err := s.ThresholdTemplates().Duplicate(ctx, id, "E1 null copy")
		dao13ePGCheck(t, err)
		row, err := s.ThresholdTemplates().Get(ctx, copyID)
		dao13ePGCheck(t, err)
		if row.ResponseID != nil {
			t.Errorf("null default became %v", row.ResponseID)
		}
	})
	t.Run("DeleteResponseClearsBoth", func(t *testing.T) {
		dao13ePGCheck(t, s.Responses().Delete(ctx, r1))
		for _, id := range []int{source, copyID} {
			row, err := s.ThresholdTemplates().Get(ctx, id)
			dao13ePGCheck(t, err)
			if row.ResponseID != nil {
				t.Errorf("template %d still has default %v", id, row.ResponseID)
			}
		}
	})
}

func TestDao13e_R0_FixedDuplicate(t *testing.T) {
	s := newPostgresContractBackend(t).Store()
	ctx := context.Background()
	response, err := s.Responses().Create(ctx, &store.Response{Name: "fixed default", Enabled: true})
	dao13ePGCheck(t, err)
	source, err := s.ThresholdTemplates().Create(ctx, &store.ThresholdTemplate{Name: "fixed source", ResponseID: &response})
	dao13ePGCheck(t, err)
	copyID, err := s.ThresholdTemplates().Duplicate(ctx, source, "fixed copy")
	dao13ePGCheck(t, err)
	row, err := s.ThresholdTemplates().Get(ctx, copyID)
	dao13ePGCheck(t, err)
	if row.ResponseID == nil || *row.ResponseID != response {
		t.Errorf("copy default=%v want=%d", row.ResponseID, response)
	}
}
