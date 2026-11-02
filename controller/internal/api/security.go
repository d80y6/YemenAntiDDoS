package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

const headerMask = "******"

func validRouteMapName(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.')
	}) < 0
}

func maskHeaders(raw json.RawMessage) json.RawMessage {
	var headers map[string]string
	if json.Unmarshal(raw, &headers) != nil {
		return json.RawMessage("null")
	}
	for key := range headers {
		headers[key] = headerMask
	}
	masked, _ := json.Marshal(headers)
	return masked
}

// Marshal a response copy; never modify repository-owned rows or historical data.
func maskWebhookValue(value any) json.RawMessage {
	raw, _ := json.Marshal(value)
	var v any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&v) != nil {
		return json.RawMessage("null")
	}
	var mask func(any)
	mask = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for key, child := range x {
				if strings.EqualFold(key, "headers") {
					raw, _ := json.Marshal(child)
					x[key] = maskHeaders(raw)
				} else {
					mask(child)
				}
			}
		case []any:
			for _, child := range x {
				mask(child)
			}
		}
	}
	mask(v)
	raw, _ = json.Marshal(v)
	return raw
}

func mergeWebhookHeaders(raw, old json.RawMessage, changedURL bool) (json.RawMessage, error) {
	var incoming, stored map[string]string
	if json.Unmarshal(raw, &incoming) != nil {
		return raw, nil
	}
	_ = json.Unmarshal(old, &stored)
	for key, value := range incoming {
		if value != headerMask {
			continue
		}
		original, exists := stored[key]
		if !exists {
			return nil, fmt.Errorf("header %s: masked value has no stored original", key)
		}
		if changedURL {
			return nil, fmt.Errorf("url changed: header values must be re-entered")
		}
		incoming[key] = original
	}
	merged, _ := json.Marshal(incoming)
	return merged, nil
}

func ipv6DefaultPrefix(s string) bool {
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		return false
	}
	ones, bits := network.Mask.Size()
	return bits == 128 && ones == 0
}

var webhookHTTPStatus = regexp.MustCompile(`^HTTP [0-9]{3}`)

func safeWebhookLog(row store.ActionExecutionLog) store.ActionExecutionLog {
	if row.ActionType == "webhook" && row.ErrorMessage != "" {
		if status := webhookHTTPStatus.FindString(row.ErrorMessage); status != "" {
			row.ErrorMessage = status
		} else {
			row.ErrorMessage = "webhook error (details redacted)"
		}
	}
	return row
}
