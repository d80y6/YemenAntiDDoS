package main

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/config"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus"
)

func TestDao7yi_H1_HTTPServerClosedNotFatal(t *testing.T) {
	old := httpFatalf
	defer func() { httpFatalf = old }()
	fatals := 0
	httpFatalf = func(string, ...any) { fatals++ }
	srv := &http.Server{}
	// A closed server returns ErrServerClosed before trying to bind a port.
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if err := serveHTTP(srv); !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("serveHTTP=%v", err)
	}
	if fatals != 0 {
		t.Errorf("ErrServerClosed fatal calls=%d want=0", fatals)
	}

	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	ast.Inspect(f, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
			return true
		}
		id, ok := a.Lhs[0].(*ast.Ident)
		if !ok || id.Name != "httpSrv" {
			return true
		}
		u, ok := a.Rhs[0].(*ast.UnaryExpr)
		if !ok {
			t.Fatal("httpSrv must be explicit server")
		}
		lit, ok := u.X.(*ast.CompositeLit)
		if !ok {
			t.Fatal("httpSrv must be server literal")
		}
		for _, e := range lit.Elts {
			kv := e.(*ast.KeyValueExpr)
			key := kv.Key.(*ast.Ident).Name
			if key == "ReadTimeout" || key == "WriteTimeout" {
				t.Errorf("unexpected total timeout %s", key)
			}
			if key == "ReadHeaderTimeout" {
				// Evaluate the actual literal expression with time.Second's Go constant.
				pkg := types.NewPackage("dao7", "dao7")
				tp := types.NewPackage("time", "time")
				tp.Scope().Insert(types.NewConst(token.NoPos, tp, "Second", types.Typ[types.Int64], constant.MakeInt64(int64(time.Second))))
				pkg.Scope().Insert(types.NewPkgName(token.NoPos, pkg, "time", tp))
				info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
				if err := types.CheckExpr(token.NewFileSet(), pkg, token.NoPos, kv.Value, info); err != nil {
					t.Fatal(err)
				}
				value, ok := constant.Int64Val(info.Types[kv.Value].Value)
				if !ok || time.Duration(value) != 10*time.Second {
					t.Errorf("ReadHeaderTimeout=%d want 10s", value)
				}
				count++
			}
		}
		return true
	})
	if count != 1 {
		t.Errorf("ReadHeaderTimeout count=%d want=1", count)
	}
}

func TestDao7yi_H2_ShutdownOrder(t *testing.T) {
	path := "main.go"
	if source := os.Getenv("DAO7YI_STATIC_MAIN"); source != "" {
		path = source // Mutation overlay counterpart for this source-reading gate.
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(data), "sig := <-sigCh", 2)
	if len(parts) != 2 {
		t.Fatal("shutdown segment absent")
	}
	segment := strings.SplitN(parts[1], "\n}", 2)[0]
	previous := -1
	for _, call := range []string{"cancel()", "httpSrv.Shutdown(", "grpcSrv.GracefulStop()", "actionEngine.Drain("} {
		at := strings.Index(segment, call)
		if strings.Count(segment, call) != 1 || at <= previous {
			t.Errorf("shutdown order/count invalid for %s in %s", call, segment)
		}
		previous = at
	}
	if httpShutdownLimit != 5*time.Second {
		t.Errorf("HTTP shutdown limit=%v want 5s", httpShutdownLimit)
	}
}

type dao7MetricStore struct{ store.Store }
type dao7MetricBGP struct{ store.BGPAnnouncementRepo }
type dao7MetricXDrop struct{ store.XDropActiveRuleRepo }
type dao7MetricScheduled struct{ store.ScheduledActionRepo }

func (dao7MetricStore) BGPAnnouncements() store.BGPAnnouncementRepo               { return dao7MetricBGP{} }
func (dao7MetricStore) XDropActiveRules() store.XDropActiveRuleRepo               { return dao7MetricXDrop{} }
func (dao7MetricStore) ScheduledActions() store.ScheduledActionRepo               { return dao7MetricScheduled{} }
func (dao7MetricBGP) CountByStatus(context.Context) (map[string]int, error)       { return nil, nil }
func (dao7MetricXDrop) CountByStatus(context.Context) (map[string]int, error)     { return nil, nil }
func (dao7MetricScheduled) CountByStatus(context.Context) (map[string]int, error) { return nil, nil }

func TestDao7yi_R2_StartupWarningAndGatheredGauge(t *testing.T) {
	cfg := &config.Config{Ring: config.RingConfig{MaxGlobalKeys: 200000, MaxPointsPerIP: 120}}
	want := config.RingEstimateBytes(cfg)
	if want <= 8*1024*1024*1024 {
		t.Fatal("fixture must exceed 8 GiB")
	}
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg, dao7MetricStore{}, &tracker.Tracker{}); err != nil {
		t.Fatal(err)
	}
	old := log.Writer()
	defer log.SetOutput(old)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	reportRingEstimate(cfg)
	if n := strings.Count(logs.String(), "WARN"); n != 1 {
		t.Errorf("startup WARN lines=%d want=1: %s", n, logs.String())
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, mf := range families {
		if mf.GetName() == "xsight_ring_estimated_memory_bytes" {
			found++
			if len(mf.Metric) != 1 || mf.Metric[0].GetGauge().GetValue() != float64(want) {
				t.Errorf("gathered gauge=%v want=%d", mf, want)
			}
		}
	}
	if found != 1 {
		t.Errorf("registered ring gauge families=%d want=1", found)
	}
	logs.Reset()
	cfg.Ring.MaxGlobalKeys = 100000
	reportRingEstimate(cfg)
	if logs.Len() != 0 {
		t.Errorf("default estimate should not warn: %s", logs.String())
	}
}
