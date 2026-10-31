package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/littlewolf9527/xsight/controller/internal/metrics"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// isIPv4MappedPrefix checks the original address independently of mask syntax.
func isIPv4MappedPrefix(cidr string) bool {
	address, _, _ := strings.Cut(cidr, "/")
	if ip, err := netip.ParseAddr(address); err == nil && ip.Is4In6() {
		return true
	}
	ip := net.ParseIP(address)
	return strings.Contains(address, ":") && ip != nil && ip.To4() != nil
}

func listPrefixes(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		prefixes, err := deps.Store.Prefixes().ListTree(c)
		if err != nil {
			dbError(c, "", err)
			return
		}
		ok(c, prefixes)
	}
}

func createPrefix(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Prefix              string `json:"prefix" binding:"required"`
			ParentID            *int   `json:"parent_id"`
			ThresholdTemplateID *int   `json:"threshold_template_id"`
			Name                string `json:"name"`
			IPGroup             string `json:"ip_group"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if isIPv4MappedPrefix(req.Prefix) {
			errResponse(c, http.StatusBadRequest, "Use IPv4 notation for IPv4-mapped prefixes")
			return
		}
		// ::/0 is not allowed — use 0.0.0.0/0 for global threshold (covers both IPv4 and IPv6)
		if ipv6DefaultPrefix(req.Prefix) {
			errResponse(c, http.StatusBadRequest, "Use 0.0.0.0/0 for global threshold (covers both IPv4 and IPv6)")
			return
		}
		if req.ParentID != nil {
			cycle, found, err := parentChainHasCycle(c, deps.Store, 0, *req.ParentID)
			if err != nil {
				dbError(c, "", err)
				return
			}
			if !found {
				errResponse(c, http.StatusBadRequest, "parent_id not found")
				return
			}
			if cycle {
				errResponse(c, http.StatusBadRequest, "parent_id would create a cycle")
				return
			}
		}
		if isGlobalPrefix(req.Prefix) && req.ThresholdTemplateID != nil {
			if !globalTemplateAllowed(c, deps.Store, *req.ThresholdTemplateID) {
				return
			}
		}
		id, err := deps.Store.Prefixes().Create(c, &store.WatchPrefix{
			Prefix: req.Prefix, ParentID: req.ParentID, ThresholdTemplateID: req.ThresholdTemplateID,
			Name: req.Name, IPGroup: req.IPGroup, Enabled: true,
		})
		if err != nil {
			dbError(c, "", err)
			return
		}
		// Trigger config push to nodes
		publishAfterChange(c, deps, "watch_prefix", strconv.Itoa(id), "create", makeDiff(nil, store.WatchPrefix{
			ID: id, Prefix: req.Prefix, ParentID: req.ParentID, ThresholdTemplateID: req.ThresholdTemplateID,
			Name: req.Name, IPGroup: req.IPGroup, Enabled: true,
		}))
		created(c, gin.H{"id": id})
	}
}

func getPrefix(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		p, err := deps.Store.Prefixes().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "prefix not found")
			return
		}
		ok(c, p)
	}
}

func updatePrefix(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		// Use a map to detect which fields were actually sent
		var raw map[string]any
		if err := c.ShouldBindJSON(&raw); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		p, err := deps.Store.Prefixes().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "prefix not found")
			return
		}
		oldP := *p // snapshot before modification
		if v, ok := raw["prefix"]; ok && v != nil {
			if s, ok := v.(string); ok {
				if isIPv4MappedPrefix(s) {
					errResponse(c, http.StatusBadRequest, "Use IPv4 notation for IPv4-mapped prefixes")
					return
				}
				if ipv6DefaultPrefix(s) {
					errResponse(c, http.StatusBadRequest, "Use 0.0.0.0/0 for global threshold (covers both IPv4 and IPv6)")
					return
				}
				p.Prefix = s
			}
		}
		if v, ok := raw["name"]; ok && v != nil {
			if s, ok := v.(string); ok {
				p.Name = s
			}
		}
		if v, ok := raw["ip_group"]; ok && v != nil {
			if s, ok := v.(string); ok {
				p.IPGroup = s
			}
		}
		if v, ok := raw["parent_id"]; ok {
			if v == nil {
				p.ParentID = nil
			} else if f, ok := v.(float64); ok {
				pid := int(f)
				cycle, found, err := parentChainHasCycle(c, deps.Store, id, pid)
				if err != nil {
					dbError(c, "", err)
					return
				}
				if !found {
					errResponse(c, http.StatusBadRequest, "parent_id not found")
					return
				}
				if cycle {
					errResponse(c, http.StatusBadRequest, "parent_id would create a cycle")
					return
				}
				p.ParentID = &pid
			}
		}
		if v, ok := raw["threshold_template_id"]; ok {
			if v == nil {
				p.ThresholdTemplateID = nil
			} else if f, ok := v.(float64); ok {
				tid := int(f)
				p.ThresholdTemplateID = &tid
			}
		}
		if v, ok := raw["enabled"]; ok && v != nil {
			if b, ok := v.(bool); ok {
				p.Enabled = b
			}
		}
		if isGlobalPrefix(p.Prefix) && p.ThresholdTemplateID != nil {
			if !globalTemplateAllowed(c, deps.Store, *p.ThresholdTemplateID) {
				return
			}
		}
		if err := deps.Store.Prefixes().Update(c, p); err != nil {
			dbError(c, "", err)
			return
		}
		publishAfterChange(c, deps, "watch_prefix", strconv.Itoa(id), "update", makeDiff(oldP, p))
		ok(c, gin.H{"ok": true})
	}
}

// parentChainHasCycle checks one proposed link against the current prefix snapshot.
// found reports whether the candidate parent exists; create and update both require it.
func parentChainHasCycle(ctx context.Context, s store.Store, selfID, parentID int) (cycle, found bool, err error) {
	prefixes, err := s.Prefixes().List(ctx)
	if err != nil {
		return false, false, err
	}
	parents := make(map[int]*int, len(prefixes))
	for _, p := range prefixes {
		parents[p.ID] = p.ParentID
	}
	_, found = parents[parentID]
	visited := make(map[int]bool)
	for current := &parentID; current != nil; current = parents[*current] {
		if (selfID != 0 && *current == selfID) || visited[*current] {
			return true, found, nil
		}
		visited[*current] = true
	}
	return false, found, nil
}

func deletePrefix(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, _ := deps.Store.Prefixes().Get(c, id)
		if err := deps.Store.Prefixes().Delete(c, id); err != nil {
			dbError(c, "", err)
			return
		}
		publishAfterChange(c, deps, "watch_prefix", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}

// publishAfterChange triggers ConfigPublisher + threshold tree rebuild.
// Extracts user_id from JWT context for audit trail.
// diff is optional JSON describing old/new values.
func publishAfterChange(c *gin.Context, deps Dependencies, entityType, entityID, action string, diff json.RawMessage) {
	if deps.ConfigPub == nil {
		return
	}
	if deps.ThreshTree != nil {
		if err := deps.ThreshTree.Rebuild(c, deps.Store); err != nil {
			log.Printf("ERROR api: rebuild threshold tree after %s %s %s: %v", entityType, action, entityID, err)
			metrics.ConfigPublishFailures.WithLabelValues("rebuild").Inc()
		}
	}
	var userID *int
	if uid, exists := c.Get("user_id"); exists {
		id := uid.(int)
		userID = &id
	}
	if entityType == "webhook_connector" || entityType == "webhook" || entityType == "response_action" {
		diff = maskWebhookValue(diff)
	}
	if _, err := deps.ConfigPub.Publish(c, userID, entityType, entityID, action, diff); err != nil {
		log.Printf("ERROR api: publish config after %s %s %s: %v", entityType, action, entityID, err)
		metrics.ConfigPublishFailures.WithLabelValues("publish").Inc()
	}
}

// makeDiff creates a JSON diff from old and new values.
func makeDiff(old, new any) json.RawMessage {
	d, _ := json.Marshal(map[string]any{"old": old, "new": new})
	return d
}

// globalTemplateAllowed writes the rejection response when a binding is invalid.
func globalTemplateAllowed(c *gin.Context, s store.Store, templateID int) bool {
	template, err := s.ThresholdTemplates().Get(c, templateID)
	if errors.Is(err, pgx.ErrNoRows) {
		errResponse(c, http.StatusBadRequest, "threshold_template_id not found")
		return false
	}
	if err != nil {
		dbError(c, "failed to check template responses: ", err)
		return false
	}
	rules, err := s.ThresholdTemplates().ListRules(c, templateID)
	if err != nil {
		dbError(c, "failed to check template responses: ", err)
		return false
	}
	candidates := []*int{template.ResponseID}
	for _, rule := range rules {
		candidates = append(candidates, rule.ResponseID)
	}
	for _, responseID := range candidates {
		if responseID == nil {
			continue
		}
		has, err := responseHasXDropOrBGP(c, s, *responseID)
		if err != nil {
			dbError(c, "failed to check template responses: ", err)
			return false
		}
		if has {
			errResponse(c, http.StatusBadRequest, "Global prefix (0.0.0.0/0) cannot use responses containing xDrop/BGP actions")
			return false
		}
	}
	return true
}
