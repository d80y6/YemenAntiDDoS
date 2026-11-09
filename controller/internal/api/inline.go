package api

import (
	"net/http"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/ingestion"
	"github.com/gin-gonic/gin"
)

// getInlineMitigations lists every attack currently mitigated at the XDP data
// plane, including which nodes hold the rules and whether the rule set is in
// the broad or narrowed phase.
func getInlineMitigations(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		if deps.Inline == nil {
			ok(c, gin.H{"enabled": false, "mitigations": []action.InlineMitigation{}})
			return
		}
		active, pushes, failures := deps.Inline.Stats()
		ok(c, gin.H{
			"enabled":     true,
			"active":      active,
			"pushes":      pushes,
			"push_errors": failures,
			"mitigations": deps.Inline.ActiveMitigations(),
		})
	}
}

// getNodePosture returns the last reported data-plane posture for one node:
// XDP attach mode, installed filter rule count, SYN-cookie counters, AF_XDP
// health and CPU pinning.
func getNodePosture(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if deps.NodeState == nil {
			ok(c, gin.H{"node_id": id, "available": false})
			return
		}
		posture, found := deps.NodeState.GetPosture(id)
		if !found {
			ok(c, gin.H{"node_id": id, "available": false})
			return
		}
		ok(c, gin.H{"node_id": id, "available": true, "posture": posture})
	}
}

// listNodePosture returns posture for every node that has reported it.
func listNodePosture(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		if deps.NodeState == nil {
			ok(c, map[string]ingestion.NodePosture{})
			return
		}
		ok(c, deps.NodeState.AllPosture())
	}
}

// reconcileInline re-pushes the authoritative inline rule snapshot to every
// connected node. Drift correction after a partial push or a NIC reset.
func reconcileInline(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		if deps.Inline == nil {
			errResponse(c, http.StatusServiceUnavailable, "inline mitigator disabled")
			return
		}
		deps.Inline.ReconcileAll()
		active, pushes, failures := deps.Inline.Stats()
		ok(c, gin.H{"active": active, "pushes": pushes, "push_errors": failures})
	}
}
