package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// --- Webhook Connectors (Response System v2) ---

func validateWebhookConnector(req *store.WebhookConnector) error {
	m := strings.ToUpper(strings.TrimSpace(req.Method))
	if m != "" && action.WebhookMethod(m) != m {
		return fmt.Errorf("method must be one of: POST, PUT, PATCH; got %q", req.Method)
	}
	req.Method = action.WebhookMethod(m)
	if req.TimeoutMs < 0 {
		return fmt.Errorf("timeout_ms must be >= 0, got %d", req.TimeoutMs)
	}
	if len(req.Headers) > 0 {
		var headers map[string]any
		if err := json.Unmarshal(req.Headers, &headers); err != nil {
			return fmt.Errorf("headers must be a JSON object with string values")
		}
		for _, value := range headers {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("headers must be a JSON object with string values")
			}
		}
	}
	return nil
}

func listWebhookConnectors(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		connectors, err := deps.Store.WebhookConnectors().List(c)
		if err != nil {
			dbError(c, "", err)
			return
		}
		ok(c, maskWebhookValue(connectors))
	}
}

func createWebhookConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req store.WebhookConnector
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Name == "" {
			errResponse(c, http.StatusBadRequest, "name is required")
			return
		}
		if req.URL == "" {
			errResponse(c, http.StatusBadRequest, "url is required")
			return
		}
		if err := validateWebhookConnector(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.TimeoutMs == 0 {
			req.TimeoutMs = 10000
		}
		req.Enabled = true

		id, err := deps.Store.WebhookConnectors().Create(c, &req)
		if err != nil {
			dbError(c, "", err)
			return
		}
		req.ID = id
		publishAfterChange(c, deps, "webhook_connector", strconv.Itoa(id), "create", makeDiff(nil, req))
		created(c, gin.H{"id": id})
	}
}

func getWebhookConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.WebhookConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "webhook connector not found")
			return
		}
		ok(c, maskWebhookValue(conn))
	}
}

func updateWebhookConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, err := deps.Store.WebhookConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "webhook connector not found")
			return
		}
		req := *old
		req.Headers = nil
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Name == "" {
			errResponse(c, http.StatusBadRequest, "name is required")
			return
		}
		if req.URL == "" {
			errResponse(c, http.StatusBadRequest, "url is required")
			return
		}
		headersProvided := len(req.Headers) > 0
		if !headersProvided {
			if req.URL != old.URL && len(old.Headers) > 0 {
				var headers map[string]any
				if json.Unmarshal(old.Headers, &headers) != nil || len(headers) > 0 {
					errResponse(c, http.StatusBadRequest, "url changed: header values must be re-entered")
					return
				}
			}
			req.Headers = old.Headers
		}
		if err := validateWebhookConnector(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if headersProvided {
			req.Headers, err = mergeWebhookHeaders(req.Headers, old.Headers, req.URL != old.URL)
			if err != nil {
				errResponse(c, http.StatusBadRequest, err.Error())
				return
			}
		}
		req.ID = id
		if err := deps.Store.WebhookConnectors().Update(c, &req); err != nil {
			dbError(c, "", err)
			return
		}
		publishAfterChange(c, deps, "webhook_connector", strconv.Itoa(id), "update", makeDiff(old, req))
		ok(c, gin.H{"ok": true})
	}
}

func deleteWebhookConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		// Check if any action references this webhook connector (fail closed on error)
		count, err := deps.Store.Responses().CountActionsByWebhookConnector(c, id)
		if err != nil {
			dbError(c, "failed to check connector usage: ", err)
			return
		}
		if count > 0 {
			errResponse(c, http.StatusConflict,
				fmt.Sprintf("webhook connector in use by %d action(s)", count))
			return
		}
		old, _ := deps.Store.WebhookConnectors().Get(c, id)
		if err := deps.Store.WebhookConnectors().Delete(c, id); err != nil {
			dbError(c, "", err)
			return
		}
		publishAfterChange(c, deps, "webhook_connector", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}

func testWebhookConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.WebhookConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "webhook connector not found")
			return
		}

		// Build test payload
		testPayload := map[string]any{
			"event":     "test",
			"message":   fmt.Sprintf("Test webhook from xSight to connector %q", conn.Name),
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		body, _ := json.Marshal(testPayload)

		req, err := http.NewRequestWithContext(c, action.WebhookMethod(conn.Method), conn.URL, bytes.NewReader(body))
		if err != nil {
			errResponse(c, http.StatusBadRequest, action.SafeWebhookError(0, &url.Error{Op: "parse", Err: err}))
			return
		}
		req.Header.Set("Content-Type", "application/json")

		// Apply custom headers
		if len(conn.Headers) > 0 {
			var headers map[string]string
			if err := json.Unmarshal(conn.Headers, &headers); err == nil {
				for k, v := range headers {
					req.Header.Set(k, v)
				}
			}
		}

		timeout := time.Duration(conn.TimeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		client := &http.Client{Timeout: timeout, Transport: action.WebhookTransport}

		resp, err := client.Do(req)
		if err != nil {
			ok(c, gin.H{"success": false, "error": action.SafeWebhookError(0, err)})
			return
		}
		defer resp.Body.Close()

		ok(c, gin.H{
			"success":     resp.StatusCode >= 200 && resp.StatusCode < 300,
			"status_code": resp.StatusCode,
		})
	}
}
