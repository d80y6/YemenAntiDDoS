package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/gin-gonic/gin"
)

var vtyshHTTPTimeout = 25 * time.Second
var vtyshHTTPWaitDelay = 2 * time.Second
var errVtyshHTTPTimeout = errors.New("vtysh timed out")

func runVtyshHTTP(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = vtyshHTTPWaitDelay
	dl, _ := ctx.Deadline()
	budget := time.Until(dl)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, nil
	}
	if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success() {
		err = nil
	} else if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("%w after %s: %w", errVtyshHTTPTimeout, budget, err)
	}
	return out, err
}

// executableBGPConnector reports whether the local vtysh can drive this
// connector. Non-FRR vendors are export-only, so probes must not run FRR
// commands on the host and pretend they tested the remote speaker.
func executableBGPConnector(conn *store.BGPConnector) bool {
	v, err := flowspec.ParseVendor(conn.Vendor)
	return err == nil && v == flowspec.VendorFRR
}

func listBGPConnectors(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		list, err := deps.Store.BGPConnectors().List(c)
		if err != nil {
			dbError(c, "bgp connector ", err)
			return
		}
		ok(c, list)
	}
}

func getBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.BGPConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		ok(c, conn)
	}
}

func createBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name          string `json:"name" binding:"required"`
			VtyshPath     string `json:"vtysh_path"`
			BGPASN        *int64 `json:"bgp_asn"`
			AddressFamily string `json:"address_family"`
			Enabled       *bool  `json:"enabled"`
			Description   string `json:"description"`
			Vendor        string `json:"vendor"`
			Flowspec      *bool  `json:"flowspec_enabled"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.BGPASN == nil {
			errResponse(c, http.StatusBadRequest, "bgp_asn is required")
			return
		}
		if *req.BGPASN < 1 || *req.BGPASN > 4294967295 {
			errResponse(c, http.StatusBadRequest, fmt.Sprintf("bgp_asn must be between 1 and 4294967295, got %d", *req.BGPASN))
			return
		}
		if req.VtyshPath == "" {
			req.VtyshPath = "/usr/bin/vtysh"
		}
		// address_family is now auto-detected from the prefix at execution time.
		// Field kept for backward compatibility but not enforced.
		if req.AddressFamily == "" {
			req.AddressFamily = "auto"
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		vendor, vErr := normalizeVendor(req.Vendor)
		if vErr != nil {
			errResponse(c, http.StatusBadRequest, vErr.Error())
			return
		}
		flowspecEnabled := false
		if req.Flowspec != nil {
			flowspecEnabled = *req.Flowspec
		}
		// Only FRR is driven over vtysh; other vendors are export-only and need
		// flowspec_enabled, otherwise a Flowspec action silently becomes RTBH.
		if vendor != flowspec.VendorFRR && !flowspecEnabled {
			errResponse(c, http.StatusBadRequest, fmt.Sprintf(
				"vendor %q is export-only: set flowspec_enabled=true (RTBH cannot be applied to a non-FRR speaker)", vendor))
			return
		}
		conn := &store.BGPConnector{
			Name:            req.Name,
			VtyshPath:       req.VtyshPath,
			BGPASN:          int(*req.BGPASN),
			AddressFamily:   req.AddressFamily,
			Enabled:         enabled,
			Description:     req.Description,
			Vendor:          string(vendor),
			FlowspecEnabled: flowspecEnabled,
		}
		id, err := deps.Store.BGPConnectors().Create(c, conn)
		if err != nil {
			dbError(c, "bgp connector ", err)
			return
		}
		conn.ID = id
		publishAfterChange(c, deps, "bgp_connector", strconv.Itoa(id), "create", makeDiff(nil, conn))
		created(c, gin.H{"id": id})
	}
}

func updateBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.BGPConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		var req struct {
			Name          string  `json:"name"`
			VtyshPath     string  `json:"vtysh_path"`
			BGPASN        *int64  `json:"bgp_asn"`
			AddressFamily string  `json:"address_family"`
			Enabled       *bool   `json:"enabled"`
			Description   *string `json:"description"`
			Vendor        *string `json:"vendor"`
			Flowspec      *bool   `json:"flowspec_enabled"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		old := *conn // snapshot before mutation
		if req.Name != "" {
			conn.Name = req.Name
		}
		if req.VtyshPath != "" {
			conn.VtyshPath = req.VtyshPath
		}
		if req.BGPASN != nil {
			conn.BGPASN = int(*req.BGPASN)
		}
		if conn.BGPASN < 1 || conn.BGPASN > 4294967295 {
			errResponse(c, http.StatusBadRequest, fmt.Sprintf("bgp_asn must be between 1 and 4294967295, got %d", conn.BGPASN))
			return
		}
		if req.AddressFamily != "" {
			conn.AddressFamily = req.AddressFamily
		}
		if req.Enabled != nil {
			conn.Enabled = *req.Enabled
		}
		if req.Description != nil {
			conn.Description = *req.Description
		}
		if req.Vendor != nil {
			vendor, vErr := normalizeVendor(*req.Vendor)
			if vErr != nil {
				errResponse(c, http.StatusBadRequest, vErr.Error())
				return
			}
			conn.Vendor = string(vendor)
		}
		if req.Flowspec != nil {
			conn.FlowspecEnabled = *req.Flowspec
		}
		if vendor, vErr := normalizeVendor(conn.Vendor); vErr != nil || vendor != flowspec.VendorFRR {
			if !conn.FlowspecEnabled {
				errResponse(c, http.StatusBadRequest, fmt.Sprintf(
					"vendor %q is export-only: set flowspec_enabled=true (RTBH cannot be applied to a non-FRR speaker)", conn.Vendor))
				return
			}
		}
		if err := deps.Store.BGPConnectors().Update(c, conn); err != nil {
			dbError(c, "bgp connector ", err)
			return
		}
		if conn.Enabled && deps.ActionEngine != nil {
			go deps.ActionEngine.SweepEnabledBGPConnector(id)
		}
		publishAfterChange(c, deps, "bgp_connector", strconv.Itoa(id), "update", makeDiff(old, conn))
		ok(c, gin.H{"ok": true})
	}
}

func deleteBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		// In-use guard: reject if any response action references this connector
		count, err := deps.Store.Responses().CountActionsByBGPConnector(c, id)
		if err != nil {
			dbError(c, "bgp connector ", err)
			return
		}
		if count > 0 {
			errResponse(c, http.StatusConflict, fmt.Sprintf("connector in use by %d action(s)", count))
			return
		}
		live, err := deps.Store.BGPAnnouncements().CountLiveByConnector(c, id)
		if err != nil {
			dbError(c, "bgp connector ", err)
			return
		}
		if live > 0 {
			errResponse(c, http.StatusConflict, fmt.Sprintf("connector still has %d announcements in FRR-relevant states", live))
			return
		}
		old, _ := deps.Store.BGPConnectors().Get(c, id)
		if err := deps.Store.BGPConnectors().Delete(c, id); err != nil {
			dbError(c, "bgp connector ", err)
			return
		}
		if old != nil {
			publishAfterChange(c, deps, "bgp_connector", strconv.Itoa(id), "delete", makeDiff(old, nil))
		}
		ok(c, gin.H{"ok": true})
	}
}

// listBGPRoutes returns the current BGP RIB for the connector's address family.
func listBGPRoutes(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c, vtyshHTTPTimeout)
		defer cancel()
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.BGPConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		if !executableBGPConnector(conn) {
			errResponse(c, http.StatusConflict, fmt.Sprintf(
				"vendor %q is export-only: BGP probes run only for FRR connectors", conn.Vendor))
			return
		}
		// Show both IPv4 and IPv6 BGP RIB — partial success is OK
		var out4, out6 []byte
		var err4, err6 error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			out4, err4 = runVtyshHTTP(ctx, conn.VtyshPath, "-c", "show ip bgp ipv4 unicast")
		}()
		go func() {
			defer wg.Done()
			out6, err6 = runVtyshHTTP(ctx, conn.VtyshPath, "-c", "show ip bgp ipv6 unicast")
		}()
		wg.Wait()
		if err4 != nil && err6 != nil {
			errResponse(c, http.StatusBadGateway, fmt.Sprintf("vtysh failed: ipv4=%v ipv6=%v", err4, err6))
			return
		}
		var combined string
		if err4 == nil {
			combined += string(out4)
		}
		if err6 == nil && len(out6) > 0 && !strings.Contains(string(out6), "No BGP prefixes displayed") {
			if combined != "" {
				combined += "\n--- IPv6 ---\n"
			}
			combined += string(out6)
		}
		ok(c, gin.H{"output": combined})
	}
}

// testBGPConnector runs "vtysh -c 'show bgp summary'" to verify FRR connectivity.
func testBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c, vtyshHTTPTimeout)
		defer cancel()
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.BGPConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		if !executableBGPConnector(conn) {
			errResponse(c, http.StatusConflict, fmt.Sprintf(
				"vendor %q is export-only: BGP probes run only for FRR connectors", conn.Vendor))
			return
		}
		out, err := runVtyshHTTP(ctx, conn.VtyshPath, "-c", "show bgp summary")
		if err != nil {
			errResponse(c, http.StatusBadGateway, fmt.Sprintf("vtysh failed: %v\n%s", err, strings.TrimSpace(string(out))))
			return
		}
		ok(c, gin.H{"ok": true, "output": string(out)})
	}
}
