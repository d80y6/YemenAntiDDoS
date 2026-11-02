package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// --- xDrop Connectors (Response System v2) ---

// maskAPIKey returns the last 4 characters prefixed with "***",
// or "***" if the key is too short.
func maskAPIKey(key string) string {
	if len(key) <= 4 {
		return "***"
	}
	return "***" + key[len(key)-4:]
}

// xDropConnectorView is a JSON-safe view with the API key masked.
type xDropConnectorView struct {
	ID           int       `json:"id"`
	Name         string    `json:"name"`
	APIURL       string    `json:"api_url"`
	APIKeyMasked string    `json:"api_key"`
	TimeoutMs    int       `json:"timeout_ms"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func toXDropView(c *store.XDropConnector) xDropConnectorView {
	return xDropConnectorView{
		ID:           c.ID,
		Name:         c.Name,
		APIURL:       c.APIURL,
		APIKeyMasked: maskAPIKey(c.APIKey),
		TimeoutMs:    c.TimeoutMs,
		Enabled:      c.Enabled,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}
}

func listXDropConnectors(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		connectors, err := deps.Store.XDropConnectors().List(c)
		if err != nil {
			dbError(c, "", err)
			return
		}
		views := make([]xDropConnectorView, len(connectors))
		for i := range connectors {
			views[i] = toXDropView(&connectors[i])
		}
		ok(c, views)
	}
}

func createXDropConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name      string `json:"name"`
			APIURL    string `json:"api_url"`
			APIKey    string `json:"api_key"`
			TimeoutMs int    `json:"timeout_ms"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Name == "" {
			errResponse(c, http.StatusBadRequest, "name is required")
			return
		}
		if req.APIURL == "" {
			errResponse(c, http.StatusBadRequest, "api_url is required")
			return
		}
		if req.APIKey == "" {
			errResponse(c, http.StatusBadRequest, "api_key is required")
			return
		}
		if req.TimeoutMs == 0 {
			req.TimeoutMs = 10000
		}

		conn := &store.XDropConnector{
			Name:      req.Name,
			APIURL:    strings.TrimRight(req.APIURL, "/"),
			APIKey:    req.APIKey,
			TimeoutMs: req.TimeoutMs,
			Enabled:   true,
		}
		id, err := deps.Store.XDropConnectors().Create(c, conn)
		if err != nil {
			dbError(c, "", err)
			return
		}
		conn.ID = id
		publishAfterChange(c, deps, "xdrop_connector", strconv.Itoa(id), "create", makeDiff(nil, toXDropView(conn)))
		created(c, gin.H{"id": id})
	}
}

func getXDropConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.XDropConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "xdrop connector not found")
			return
		}
		ok(c, toXDropView(conn))
	}
}

func updateXDropConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, err := deps.Store.XDropConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "xdrop connector not found")
			return
		}

		var req struct {
			Name      *string `json:"name"`
			APIURL    *string `json:"api_url"`
			APIKey    string  `json:"api_key"`
			TimeoutMs *int    `json:"timeout_ms"`
			Enabled   *bool   `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}

		conn := *old
		if req.Name != nil {
			conn.Name = *req.Name
			if conn.Name == "" {
				errResponse(c, http.StatusBadRequest, "name is required")
				return
			}
		}
		if req.APIURL != nil {
			conn.APIURL = strings.TrimRight(*req.APIURL, "/")
			if conn.APIURL == "" {
				errResponse(c, http.StatusBadRequest, "api_url is required")
				return
			}
		}
		if req.TimeoutMs != nil {
			conn.TimeoutMs = *req.TimeoutMs
		}
		if req.Enabled != nil {
			conn.Enabled = *req.Enabled
		}
		if conn.APIURL != old.APIURL && req.APIKey == "" {
			errResponse(c, http.StatusBadRequest, "api_url changed: api_key must be re-entered")
			return
		}
		// If no new API key provided, keep the old one
		if req.APIKey != "" {
			conn.APIKey = req.APIKey
		}

		if err := deps.Store.XDropConnectors().Update(c, &conn); err != nil {
			dbError(c, "", err)
			return
		}
		publishAfterChange(c, deps, "xdrop_connector", strconv.Itoa(id), "update", makeDiff(toXDropView(old), toXDropView(&conn)))
		ok(c, gin.H{"ok": true})
	}
}

func deleteXDropConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		// Check if any action targets this connector (fail closed on error)
		count, err := deps.Store.XDropTargets().CountByConnector(c, id)
		if err != nil {
			dbError(c, "failed to check connector usage: ", err)
			return
		}
		if count > 0 {
			errResponse(c, http.StatusConflict,
				fmt.Sprintf("xDrop connector in use by %d action(s)", count))
			return
		}
		live, err := deps.Store.XDropActiveRules().CountLiveByConnector(c, id)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, "failed to check xDrop connector usage")
			return
		}
		if live > 0 {
			errResponse(c, http.StatusConflict, "xDrop connector still has active rules")
			return
		}
		old, _ := deps.Store.XDropConnectors().Get(c, id)
		if err := deps.Store.XDropConnectors().Delete(c, id); err != nil {
			dbError(c, "", err)
			return
		}
		var diff interface{}
		if old != nil {
			diff = toXDropView(old)
		}
		publishAfterChange(c, deps, "xdrop_connector", strconv.Itoa(id), "delete", makeDiff(diff, nil))
		ok(c, gin.H{"ok": true})
	}
}

func testXDropConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.XDropConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "xdrop connector not found")
			return
		}

		// Test the v3 machine credential via GET {api_url}/auth/me.
		// api_url is the versioned API base (e.g. http://host:8000/api/v1),
		// consistent with runtime execution which appends /rules.
		healthURL := strings.TrimRight(conn.APIURL, "/") + "/auth/me"
		req, err := http.NewRequestWithContext(c, http.MethodGet, healthURL, nil)
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid connector URL: "+err.Error())
			return
		}
		action.SetXDropAuth(req, conn.APIKey)

		timeout := time.Duration(conn.TimeoutMs) * time.Millisecond
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		client := &http.Client{Timeout: timeout}

		resp, err := client.Do(req)
		if err != nil {
			ok(c, gin.H{"success": false, "error": fmt.Sprintf("health check failed: %v", err)})
			return
		}
		defer resp.Body.Close()

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		var identity struct{ Kind, Name string }
		decodeErr := json.Unmarshal(body, &identity)
		success := resp.StatusCode == http.StatusOK && readErr == nil && decodeErr == nil && identity.Kind == "machine"
		result := gin.H{"success": success, "status_code": resp.StatusCode, "kind": identity.Kind, "name": identity.Name}
		if !success {
			result["error"] = "invalid xdrop machine auth response"
			if resp.StatusCode != http.StatusOK {
				result["error"] = action.XDropHTTPError(resp.StatusCode, body)
			}
		}
		ok(c, result)
	}
}
