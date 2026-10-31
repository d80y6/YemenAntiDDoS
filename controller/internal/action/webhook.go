package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type webhookRoundTripper struct{}

func (webhookRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return WebhookTransport.RoundTrip(req)
}

const defaultWebhookTimeout = 10 * time.Second

var httpClient = &http.Client{Timeout: defaultWebhookTimeout, Transport: webhookRoundTripper{}}

func webhookTimeout(ms int) time.Duration {
	if ms <= 0 || ms > int(defaultWebhookTimeout/time.Millisecond) {
		return defaultWebhookTimeout
	}
	return time.Duration(ms) * time.Millisecond
}

func webhookMethod(m string) string {
	switch method := strings.ToUpper(strings.TrimSpace(m)); method {
	case "POST", "PUT", "PATCH":
		return method
	}
	return "POST"
}

// WebhookMethod shares the execution-side method normalization with API callers.
func WebhookMethod(m string) string { return webhookMethod(m) }

func postConnectorWebhook(ctx context.Context, wc store.WebhookConnector, attack *store.Attack, eventType string, fa *FlowAnalysis) (string, error) {
	method := webhookMethod(wc.Method)
	if wc.Method != "" && method == "POST" && strings.ToUpper(strings.TrimSpace(wc.Method)) != "POST" {
		log.Printf("WARN webhook: connector %d method fallback to POST", wc.ID)
	}
	var headers map[string]string
	if len(wc.Headers) > 0 {
		if err := json.Unmarshal(wc.Headers, &headers); err != nil {
			log.Printf("webhook: malformed headers JSON — sending without custom headers")
		}
	}
	client := &http.Client{Timeout: webhookTimeout(wc.TimeoutMs), Transport: webhookRoundTripper{}}
	return postWebhookWithConfig(ctx, client, wc.URL, method, headers, attack, eventType, fa)
}

// webhookConfig is the parsed action config for webhook type.
type webhookConfig struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"` // default POST
	Headers map[string]string `json:"headers"`
}

// executeWebhook executes a webhook action from response_actions config.
func executeWebhook(ctx context.Context, configJSON []byte, attack *store.Attack, eventType string) (string, error) {
	var cfg webhookConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return "", fmt.Errorf("%s", safeWebhookError(0, errWebhookRequest))
	}
	if cfg.URL == "" {
		return "", fmt.Errorf("%s", safeWebhookError(0, errWebhookRequest))
	}
	if cfg.Method == "" {
		cfg.Method = "POST"
	}

	return postWebhookWithConfig(ctx, httpClient, cfg.URL, cfg.Method, cfg.Headers, attack, eventType, nil)
}

// postWebhookWithFA sends a webhook with optional FlowAnalysis data.
func postWebhookWithFA(ctx context.Context, url string, headersJSON json.RawMessage, attack *store.Attack, eventType string, fa *FlowAnalysis) (string, error) {
	var headers map[string]string
	if len(headersJSON) > 0 {
		if err := json.Unmarshal(headersJSON, &headers); err != nil {
			log.Printf("webhook: malformed headers JSON — sending without custom headers")
		}
	}
	return postWebhookWithConfig(ctx, httpClient, url, "POST", headers, attack, eventType, fa)
}

func postWebhookWithConfig(ctx context.Context, client *http.Client, url, method string, headers map[string]string, attack *store.Attack, eventType string, fa *FlowAnalysis) (string, error) {
	// Build payload
	payload := map[string]any{
		"event":        eventType,
		"attack_id":    attack.ID,
		"dst_ip":       attack.DstIP,
		"decoder":      attack.DecoderFamily,
		"attack_type":  attack.AttackType,
		"severity":     attack.Severity,
		"confidence":   attack.Confidence,
		"peak_pps":     attack.PeakPPS,
		"peak_bps":     attack.PeakBPS,
		"reason_codes": attack.ReasonCodes,
		"node_sources": attack.NodeSources,
		"started_at":   attack.StartedAt.Format(time.RFC3339),
		"timestamp":    time.Now().Format(time.RFC3339),
	}
	if attack.EndedAt != nil {
		payload["ended_at"] = attack.EndedAt.Format(time.RFC3339)
		payload["duration_seconds"] = int(attack.EndedAt.Sub(attack.StartedAt).Seconds())
	}
	// Include end_reason for every end event: global attack_end and response-webhook expired/evicted.
	if eventType == "attack_end" || eventType == "expired" || eventType == "evicted" {
		endReason := "expired"
		for _, rc := range attack.ReasonCodes {
			if rc == "evicted_by_cap" {
				endReason = "evicted_by_cap"
				break
			}
		}
		payload["end_reason"] = endReason
	}
	// Flow analysis fields (Phase 4)
	if fa != nil {
		payload["top_src_ips"] = fa.TopSrcIPs
		payload["top_src_ports"] = fa.TopSrcPorts
		payload["top_dst_ports"] = fa.TopDstPorts
		payload["dominant_src_port"] = fa.DominantSrcPort
		payload["dominant_src_port_pct"] = fa.DominantSrcPortPct
		payload["unique_src_ips"] = fa.UniqueSrcIPs
		if fa.FlowSummaryJSON != "" {
			payload["flow_summary_json"] = json.RawMessage(fa.FlowSummaryJSON)
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("%s", safeWebhookError(0, errWebhookRequest))
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("%s", safeWebhookError(0, errWebhookRequest))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xsight-controller/1.0")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s", safeWebhookError(0, err))
	}
	defer resp.Body.Close()

	result := fmt.Sprintf("HTTP %d", resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, fmt.Errorf("%s", safeWebhookError(resp.StatusCode, nil))
	}
	return result, nil
}
