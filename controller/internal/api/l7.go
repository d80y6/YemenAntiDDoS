package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// getL7Summary serves the aggregated layer-7 view: totals per decoder, a
// per-minute series for the stacked chart, top destinations/sources and the
// most recent events. The window is bounded so a console refresh cannot pull
// the whole ring.
func getL7Summary(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		if deps.L7 == nil {
			ok(c, gin.H{"enabled": false, "totals": gin.H{}, "series": []any{}})
			return
		}
		minutes := 15
		if raw := c.Query("window_minutes"); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil {
				minutes = v
			}
		}
		if minutes < 1 {
			minutes = 1
		}
		if minutes > 240 {
			minutes = 240
		}
		snap := deps.L7.Snapshot(time.Duration(minutes)*time.Minute, time.Now())
		ok(c, gin.H{
			"enabled":          true,
			"generated_at":     snap.GeneratedAt,
			"window_minutes":   snap.WindowMinutes,
			"bucket_seconds":   snap.BucketSeconds,
			"totals":           snap.Totals,
			"rates_per_second": snap.Rates,
			"series":           snap.Series,
			"targets":          snap.Targets,
			"sources":          snap.Sources,
			"nodes":            snap.Nodes,
			"ja3":              snap.JA3,
			"ja4":              snap.JA4,
			"user_agents":      snap.UserAgents,
			"recent":           snap.Recent,
			"dropped":          snap.Dropped,
		})
	}
}

// listL7Events returns the raw event ring, newest first.
func listL7Events(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		if deps.L7 == nil {
			ok(c, gin.H{"events": []any{}})
			return
		}
		limit := 100
		if raw := c.Query("limit"); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil {
				limit = v
			}
		}
		if limit < 1 || limit > 1000 {
			limit = 100
		}
		events, dropped := deps.L7.Stats()
		ok(c, gin.H{
			"events":        deps.L7.Recent(limit),
			"buffered":      events,
			"total_dropped": dropped,
		})
	}
}

// getNodeTLS reports the Controller's own server certificate plus the client
// certificate the Node presented, so operators can see mTLS state and expiry
// before a rotation turns into an outage.
func getNodeTLS(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeID := c.Param("id")
		if nodeID == "" {
			errResponse(c, http.StatusBadRequest, "node id is required")
			return
		}

		resp := gin.H{
			"node_id":  nodeID,
			"enabled":  false,
			"warnings": []string{},
		}
		var warnings []string

		if deps.TLSInfo != nil {
			if info, minVersion, enabled := deps.TLSInfo(); enabled {
				resp["enabled"] = true
				server := gin.H{
					"cert":           info,
					"min_version":    minVersion,
					"days_remaining": daysUntil(info.NotAfter),
					"not_after":      info.NotAfter,
				}
				if d := daysUntil(info.NotAfter); d >= 0 && d <= 30 {
					warnings = append(warnings, "controller_server_cert_expiring")
				}
				resp["server"] = server
			}
		}

		if deps.NodeState != nil {
			if peer, found := deps.NodeState.GetPeerTLS(nodeID); found {
				days := int(peer.NotAfter.Sub(time.Now()).Hours() / 24)
				node := gin.H{
					"present":        true,
					"mtls":           true,
					"verified":       peer.Verified,
					"identity":       peer.Identity,
					"days_remaining": days,
					"seen_at":        peer.SeenAt,
					"cert": gin.H{
						"subject":            peer.Subject,
						"issuer":             peer.Issuer,
						"serial_number":      peer.Serial,
						"not_before":         peer.NotBefore,
						"not_after":          peer.NotAfter,
						"dns_names":          peer.DNSNames,
						"uris":               peer.URIs,
						"fingerprint_sha256": peer.Fingerprint,
						"is_ca":              peer.IsCA,
					},
				}
				if days >= 0 && days <= 30 {
					warnings = append(warnings, "node_cert_expiring")
				}
				if !peer.Verified {
					warnings = append(warnings, "node_identity_unverified")
				}
				resp["node"] = node
			} else {
				resp["node"] = gin.H{"present": false}
				if enabled, _ := resp["enabled"].(bool); enabled {
					warnings = append(warnings, "no_handshake_certificate_recorded")
				}
			}
		}

		resp["warnings"] = warnings
		ok(c, resp)
	}
}

func daysUntil(rfc3339 string) int {
	if rfc3339 == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return 0
	}
	return int(time.Until(t).Hours() / 24)
}
