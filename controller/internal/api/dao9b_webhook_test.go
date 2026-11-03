package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/gin-gonic/gin"
)

func dao9bTestButton(t *testing.T, ms int, replyAfter, want time.Duration, wantSuccess bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		old := action.WebhookTransport
		t.Cleanup(func() { action.WebhookTransport = old })
		calls := 0
		action.WebhookTransport = dao3APIRoundTrip(func(r *http.Request) (*http.Response, error) {
			calls++
			if replyAfter == 0 {
				<-r.Context().Done()
				return nil, r.Context().Err()
			}
			timer := time.NewTimer(replyAfter)
			defer timer.Stop()
			select {
			case <-r.Context().Done():
				return nil, r.Context().Err()
			case <-timer.C:
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
			}
		})
		s := dao3WebhookStore()
		s.connectors[0].TimeoutMs = ms
		s.connectors[0].URL = "https://hooks.example/dao9b?token=private-url"
		w := httptest.NewRecorder()
		c, engine := gin.CreateTestContext(w)
		engine.ContextWithFallback = true
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c.Request = httptest.NewRequest(http.MethodPost, "/api/settings/webhook-connectors/1/test", nil).WithContext(ctx)
		c.Params = gin.Params{{Key: "id", Value: "1"}}
		start := time.Now()
		testWebhookConnector(Dependencies{Store: s})(c)
		elapsed := time.Since(start)
		if elapsed != want {
			t.Errorf("elapsed=%s want=%s", elapsed, want)
		}
		if w.Code != http.StatusOK || calls != 1 {
			t.Errorf("HTTP=%d transport calls=%d body=%s", w.Code, calls, w.Body.String())
		}
		var result struct {
			Success    *bool  `json:"success"`
			Error      string `json:"error"`
			StatusCode int    `json:"status_code"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Success == nil || *result.Success != wantSuccess {
			t.Errorf("success response=%s want=%v", w.Body.String(), wantSuccess)
		}
		if !wantSuccess && result.Error != "timeout" {
			t.Errorf("error=%q want=timeout", result.Error)
		}
		if wantSuccess && result.StatusCode != 200 {
			t.Errorf("remote status=%d want=200", result.StatusCode)
		}
		if strings.Contains(w.Body.String(), "private-url") {
			t.Errorf("unsafe response=%s", w.Body.String())
		}
		t.Logf("elapsed=%s requests=%d response=%s", elapsed, calls, w.Body.String())
	})
}
func TestDao9b_W8_TestButtonNegativeTimeout(t *testing.T) {
	dao9bTestButton(t, -5, 0, 10*time.Second, false)
}
func TestDao9b_W8b_TestButtonPositiveTimeoutUncapped(t *testing.T) {
	dao9bTestButton(t, 20000, 15*time.Second, 15*time.Second, true)
}
