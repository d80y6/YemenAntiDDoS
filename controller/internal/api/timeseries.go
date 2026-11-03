package api

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/gin-gonic/gin"
)

func queryTimeseries(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		resolution := c.DefaultQuery("resolution", "5min")
		// Dynamic limit based on resolution to avoid truncation
		limit := 1000
		switch resolution {
		case "5s":
			limit = 7200 // up to 10h of 5s data
		case "5min":
			limit = 2000 // up to ~7 days of 5min data
		case "1h":
			limit = 1000 // up to ~41 days of 1h data
		}
		dir := c.Query("direction")
		if dir != "" && dir != "receives" && dir != "sends" && dir != "both" {
			errResponse(c, http.StatusBadRequest, "direction must be 'receives', 'sends', or 'both'")
			return
		}
		filter := store.TimeseriesFilter{
			Prefix:        c.Query("prefix"),
			NodeID:        c.Query("node_id"),
			Resolution:    resolution,
			Direction:     dir,
			Limit:         limit,
			IncludeExtras: c.Query("include_extras") == "true",
		}
		if from := c.Query("from"); from != "" {
			if t, err := time.Parse(time.RFC3339, from); err == nil {
				filter.From = t
			}
		}
		if to := c.Query("to"); to != "" {
			if t, err := time.Parse(time.RFC3339, to); err == nil {
				filter.To = t
			}
		}
		// Default: last 1 hour
		if filter.From.IsZero() {
			filter.From = time.Now().Add(-1 * time.Hour)
		}
		if !parseTimeseriesDstIP(c, &filter) {
			return
		}

		points, err := deps.Store.Stats().QueryTimeseries(c, filter)
		if err != nil {
			dbError(c, "", err)
			return
		}
		ok(c, points)
	}
}

// parseTimeseriesDstIP applies the bounded raw-table query contract only when
// dst_ip is supplied, preserving the existing prefix query defaults.
func parseTimeseriesDstIP(c *gin.Context, filter *store.TimeseriesFilter) bool {
	raw, supplied := c.Request.URL.Query()["dst_ip"]
	if !supplied {
		return true
	}
	value := ""
	if len(raw) > 0 {
		value = raw[0]
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		prefix, prefixErr := netip.ParsePrefix(value)
		if prefixErr != nil || prefix.Bits() != prefix.Addr().BitLen() {
			errResponse(c, http.StatusBadRequest, "invalid dst_ip")
			return false
		}
		addr = prefix.Addr()
	}
	if addr.Zone() != "" {
		errResponse(c, http.StatusBadRequest, "invalid dst_ip")
		return false
	}
	if filter.Prefix != "" {
		errResponse(c, http.StatusBadRequest, "dst_ip and prefix are mutually exclusive")
		return false
	}
	if filter.Resolution != "5s" && filter.Resolution != "5min" {
		errResponse(c, http.StatusBadRequest, "dst_ip resolution must be '5s' or '5min'")
		return false
	}
	if filter.Direction == "both" {
		errResponse(c, http.StatusBadRequest, "dst_ip direction must be 'receives' or 'sends'")
		return false
	}
	if filter.To.IsZero() {
		filter.To = time.Now()
	}
	if filter.To.Sub(filter.From) > 6*time.Hour {
		errResponse(c, http.StatusBadRequest, "dst_ip queries are limited to 6h")
		return false
	}
	filter.DstIP = addr.String()
	return true
}
