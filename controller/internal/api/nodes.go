package api

import (
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func listNodes(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodes, err := deps.Store.Nodes().List(c)
		if err != nil {
			dbError(c, "", err)
			return
		}
		// Enrich with online status
		type nodeWithStatus struct {
			store.Node
			Online      bool       `json:"online"`
			LastStatsAt *time.Time `json:"last_stats_at,omitempty"`
		}
		var result []nodeWithStatus
		for _, n := range nodes {
			var lastStatsAt *time.Time
			if stamp := deps.NodeState.LastStatsAt(n.ID); !stamp.IsZero() {
				lastStatsAt = &stamp
			}
			result = append(result, nodeWithStatus{
				Node:        n,
				Online:      deps.NodeState.IsOnline(n.ID),
				LastStatsAt: lastStatsAt,
			})
		}
		ok(c, result)
	}
}

func createNode(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			ID          string `json:"id" binding:"required"`
			APIKey      string `json:"api_key" binding:"required"`
			Description string `json:"description"`
			Mode        string `json:"mode"` // "xdp" (default) | "flow"
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Mode == "" {
			req.Mode = "xdp"
		}
		if req.Mode != "xdp" && req.Mode != "flow" {
			errResponse(c, http.StatusBadRequest, "mode must be 'xdp' or 'flow'")
			return
		}
		node := &store.Node{
			ID: req.ID, APIKey: req.APIKey, Description: req.Description, Mode: req.Mode, Enabled: true,
		}
		if err := deps.Store.Nodes().Create(c, node); err != nil {
			dbError(c, "", err)
			return
		}
		auditDirect(c, deps, "node", req.ID, "create", makeDiff(nil, node))
		created(c, gin.H{"id": req.ID})
	}
}

func getNode(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		node, err := deps.Store.Nodes().Get(c, c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusNotFound, "node not found")
			return
		}
		ok(c, node)
	}
}

func updateNode(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Description string `json:"description"`
			Mode        string `json:"mode"`
			Enabled     *bool  `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Mode != "" && req.Mode != "xdp" && req.Mode != "flow" {
			errResponse(c, http.StatusBadRequest, "mode must be 'xdp' or 'flow'")
			return
		}
		node, err := deps.Store.Nodes().Get(c, c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusNotFound, "node not found")
			return
		}
		old := *node
		if req.Description != "" {
			node.Description = req.Description
		}
		if req.Mode != "" {
			node.Mode = req.Mode
		}
		if req.Enabled != nil {
			node.Enabled = *req.Enabled
		}
		if err := deps.Store.Nodes().Update(c, node); err != nil {
			dbError(c, "", err)
			return
		}
		auditDirect(c, deps, "node", node.ID, "update", makeDiff(old, node))
		ok(c, gin.H{"ok": true})
	}
}

func deleteNode(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeID := c.Param("id")
		var old any = gin.H{"id": nodeID}
		if node, err := deps.Store.Nodes().Get(c, nodeID); err == nil && node != nil {
			old = *node
		}
		// Cascade: delete flow listeners (sources cascade via FK) before deleting node
		listeners, err := deps.Store.FlowListeners().List(c, nodeID)
		if err != nil {
			dbError(c, "failed to list flow listeners: ", err)
			return
		}
		for _, l := range listeners {
			if err := deps.Store.FlowListeners().Delete(c, l.ID); err != nil {
				dbError(c, "failed to delete flow listener: ", err)
				return
			}
		}
		if err := deps.Store.Nodes().Delete(c, nodeID); err != nil {
			dbError(c, "", err)
			return
		}
		auditDirect(c, deps, "node", nodeID, "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}

func getNodeStatus(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		node, err := deps.Store.Nodes().Get(c, c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusNotFound, "node not found")
			return
		}
		online := deps.NodeState.IsOnline(node.ID)
		lastStats := deps.NodeState.LastStatsAt(node.ID)
		drift := node.DeliveryVersionCurrent - node.DeliveryVersionApplied

		status := gin.H{
			"id":                       node.ID,
			"mode":                     node.Mode,
			"online":                   online,
			"config_status":            node.ConfigStatus,
			"delivery_version_current": node.DeliveryVersionCurrent,
			"delivery_version_applied": node.DeliveryVersionApplied,
			"drift":                    drift,
			"last_ack_at":              node.LastACKAt,
		}
		if !lastStats.IsZero() {
			status["last_stats_at"] = lastStats
			status["stats_age_seconds"] = int(time.Since(lastStats).Seconds())
		}
		connAt := deps.NodeState.ConnectedAt(node.ID)
		if !connAt.IsZero() {
			status["connected_at"] = connAt
			status["uptime_seconds"] = int(time.Since(connAt).Seconds())
		}
		// Flow node metrics (decode errors, unknown exporter, template misses)
		if fm := deps.NodeState.GetFlowMetrics(node.ID); fm != nil {
			status["flow_metrics"] = fm
		}
		if ss := deps.NodeState.GetSourceStatuses(node.ID); len(ss) > 0 {
			status["source_statuses"] = ss
		}
		if ls := deps.NodeState.GetListenerStatuses(node.ID); len(ls) > 0 {
			status["listener_statuses"] = ls
		}
		if interfaces := deps.NodeState.GetInterfaces(node.ID); len(interfaces) > 0 {
			status["interfaces"] = interfaces
		}
		if capture := deps.NodeState.GetCapture(node.ID); len(capture) > 0 {
			type captureInfo struct {
				Interface          string `json:"interface"`
				UpstreamSampleRate uint32 `json:"upstream_sample_rate"`
			}
			items := make([]captureInfo, 0, len(capture))
			for name, rate := range capture {
				items = append(items, captureInfo{Interface: name, UpstreamSampleRate: rate})
			}
			sort.Slice(items, func(i, j int) bool { return items[i].Interface < items[j].Interface })
			status["capture"] = items
		}
		ok(c, status)
	}
}
