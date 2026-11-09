package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/gin-gonic/gin"
)

func bgpVendorRequest(t *testing.T, s *dao11cStore, method, target, body, id string, h gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: id}}
	c.Request = httptest.NewRequest(method, target, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h(c)
	return w
}

// Export-only vendors must opt into Flowspec: otherwise a BGP action would be
// silently converted into an RTBH attempt against a non-FRR speaker.
func TestBgpVendorCreateRequiresFlowspec(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"cisco_rtbh_rejected", `{"name":"c1","bgp_asn":65000,"vendor":"cisco_xr"}`, http.StatusBadRequest},
		{"juniper_explicit_false_rejected", `{"name":"j1","bgp_asn":65000,"vendor":"juniper","flowspec_enabled":false}`, http.StatusBadRequest},
		{"arista_flowspec_ok", `{"name":"a1","bgp_asn":65000,"vendor":"arista","flowspec_enabled":true}`, http.StatusCreated},
		{"frr_rtbh_ok", `{"name":"f1","bgp_asn":65000,"vendor":"frr"}`, http.StatusCreated},
		{"legacy_empty_vendor_ok", `{"name":"l1","bgp_asn":65000}`, http.StatusCreated},
		{"unknown_vendor_rejected", `{"name":"u1","bgp_asn":65000,"vendor":"bogus","flowspec_enabled":true}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dao11cFixture()
			w := bgpVendorRequest(t, s, http.MethodPost, "/api/settings/bgp-connectors", tc.body, "",
				createBGPConnector(Dependencies{Store: s}))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestBgpVendorUpdateRequiresFlowspec(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := dao11cFixture()
	update := updateBGPConnector(Dependencies{Store: s})

	w := bgpVendorRequest(t, s, http.MethodPut, "/api/settings/bgp-connectors/1",
		`{"vendor":"cisco_xr"}`, "1", update)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("switch to cisco_xr without flowspec = %d, want 400: %s", w.Code, w.Body.String())
	}
	// A rejected update must not persist the partial mutation.
	conn, err := s.BGPConnectors().Get(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if conn.Vendor != "" && conn.Vendor != "frr" {
		t.Fatalf("rejected update persisted vendor %q", conn.Vendor)
	}

	w = bgpVendorRequest(t, s, http.MethodPut, "/api/settings/bgp-connectors/1",
		`{"vendor":"cisco_xr","flowspec_enabled":true}`, "1", update)
	if w.Code != http.StatusOK {
		t.Fatalf("switch to cisco_xr with flowspec = %d, want 200: %s", w.Code, w.Body.String())
	}
	conn, err = s.BGPConnectors().Get(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if conn.Vendor != "cisco_xr" || !conn.FlowspecEnabled {
		t.Fatalf("stored vendor=%q flowspec=%t, want cisco_xr/true", conn.Vendor, conn.FlowspecEnabled)
	}
}

// Probes drive the local vtysh, so they must refuse export-only connectors
// instead of reporting a result from the host's FRR.
func TestBgpProbesRejectExportOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := dao11cFixture()
	s.bgps.rows = []store.BGPConnector{{
		ID: 1, Name: "remote", BGPASN: 65000, Enabled: true,
		Vendor: "juniper", FlowspecEnabled: true,
	}}
	for name, h := range map[string]gin.HandlerFunc{
		"test":   testBGPConnector(Dependencies{Store: s}),
		"routes": listBGPRoutes(Dependencies{Store: s}),
	} {
		t.Run(name, func(t *testing.T) {
			w := bgpVendorRequest(t, s, http.MethodPost, "/api/settings/bgp-connectors/1/"+name, "", "1", h)
			if w.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "export-only") {
				t.Fatalf("missing export-only hint: %s", w.Body.String())
			}
		})
	}
}
