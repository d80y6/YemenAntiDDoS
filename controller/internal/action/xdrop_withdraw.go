package action

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

const xdropReconcileInterval = 2 * time.Minute

type xdropRuleKey struct {
	attack, action, connector int
	rule                      string
}

func xdropKeyFromSchedule(sa store.ScheduledAction) xdropRuleKey {
	return xdropRuleKey{sa.AttackID, sa.ActionID, sa.ConnectorID, sa.ExternalRuleID}
}

func (k xdropRuleKey) String() string { return startupRuleKey(k.attack, k.action, k.connector, k.rule) }

func xdropScheduleForRule(r store.XDropActiveRule) store.ScheduledAction {
	return store.ScheduledAction{ActionType: "xdrop_unblock", AttackID: r.AttackID, ActionID: r.ActionID, ConnectorID: r.ConnectorID, ExternalRuleID: r.ExternalRuleID}
}

type xdropDeleteResult struct {
	HTTPStatus     int
	Error          error
	RemoteReleased bool
}

var xdropErrorURL = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)

func redactXDropError(detail, key string) string {
	detail = xdropErrorURL.ReplaceAllString(detail, "<url>")
	if key != "" {
		detail = strings.ReplaceAll(detail, key, "[redacted]")
	}
	return detail
}

func xdropTransportError(method string, err error) error {
	// Neither url.Error nor an inner error is safe to echo: Location parsing
	// and custom transports can include the full URL, userinfo or credentials.
	category := "transport failed"
	var network net.Error
	var parsed *url.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout() {
		category = "request timed out"
	} else if errors.As(err, &parsed) && parsed.Op == "parse" {
		category = "invalid redirect"
	} else if network != nil {
		category = "connection failed"
	}
	return fmt.Errorf("xDrop %s %s; result unknown; will retry", method, category)
}

// The caller checks cancellation before starting. Once started, release and
// bookkeeping have separate finite budgets, independent of the action deadline.
func deleteXDropClaim(conn store.XDropConnector, k xdropRuleKey) (result xdropDeleteResult) {
	defer func() {
		if result.Error != nil {
			result.Error = errors.New(redactXDropError(result.Error.Error(), conn.APIKey))
		}
	}()
	timeout := 10 * time.Second
	if conn.TimeoutMs > 0 {
		timeout = time.Duration(conn.TimeoutMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	u := strings.TrimRight(conn.APIURL, "/") + "/rules/" + url.PathEscape(k.rule) + "?claim_ref=" + url.QueryEscape(xdropClaimRef(k.attack, k.action))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return xdropDeleteResult{Error: fmt.Errorf("invalid xDrop DELETE request")}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xsight-controller/1.0")
	SetXDropAuth(req, conn.APIKey)
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return xdropDeleteResult{Error: xdropTransportError(http.MethodDelete, err)}
	}
	defer resp.Body.Close()
	result.HTTPStatus = resp.StatusCode
	if resp.StatusCode == http.StatusNoContent {
		result.RemoteReleased = true
		return result
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	detail := truncateStr(redactXDropError(XDropHTTPError(resp.StatusCode, body), conn.APIKey), 1024)
	if resp.StatusCode == http.StatusNotFound {
		detail += "; DELETE route not found; check connector API URL (expected versioned API base)"
	} else if resp.StatusCode < 400 {
		detail = "unexpected xDrop DELETE protocol response: " + detail
	}
	result.Error = fmt.Errorf("%s", detail)
	return result
}

type xdropValidateResult struct {
	RuleID   string
	NotFound bool
	Error    error
}

func xdropTimeout(conn store.XDropConnector) time.Duration {
	if conn.TimeoutMs > 0 {
		return time.Duration(conn.TimeoutMs) * time.Millisecond
	}
	return 10 * time.Second
}

// validateXDropClaim only queries a clone of the remote ledger. Its input is
// the original create body with claim_ref removed; it never renews a rule.
func validateXDropClaim(conn store.XDropConnector, body []byte) (result xdropValidateResult) {
	defer func() {
		if result.Error != nil {
			result.Error = errors.New(redactXDropError(result.Error.Error(), conn.APIKey))
		}
	}()
	timeout := xdropTimeout(conn)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	payload := append([]byte(`{"items":[`), body...)
	payload = append(payload, ']', '}')
	u := strings.TrimRight(conn.APIURL, "/") + "/rules/batch?validate=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return xdropValidateResult{Error: errors.New("invalid xDrop POST validate request")}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xsight-controller/1.0")
	SetXDropAuth(req, conn.APIKey)
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return xdropValidateResult{Error: xdropTransportError(http.MethodPost, err)}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return xdropValidateResult{Error: xdropTransportError(http.MethodPost, err)}
	}
	if resp.StatusCode != http.StatusOK {
		return xdropValidateResult{Error: fmt.Errorf("xDrop POST validate: %s", truncateStr(redactXDropError(XDropHTTPError(resp.StatusCode, data), conn.APIKey), 1024))}
	}
	var envelope struct {
		Results []struct {
			Rule *struct {
				ID *string `json:"id"`
			} `json:"rule"`
			Existing *bool `json:"existing"`
			Error    *struct {
				RuleID  string `json:"rule_id"`
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		} `json:"results"`
	}
	protocolError := xdropValidateResult{Error: errors.New("unexpected xDrop POST validate protocol response")}
	if json.Unmarshal(data, &envelope) != nil || len(envelope.Results) != 1 {
		return protocolError
	}
	item := envelope.Results[0]
	if item.Error != nil {
		if item.Error.RuleID != "" {
			return xdropValidateResult{RuleID: item.Error.RuleID}
		}
		return xdropValidateResult{Error: fmt.Errorf("xDrop POST validate: %s: %s", item.Error.Code, item.Error.Message)}
	}
	if item.Rule == nil || item.Rule.ID == nil || item.Existing == nil {
		return protocolError
	}
	if *item.Existing && *item.Rule.ID != "" {
		return xdropValidateResult{RuleID: *item.Rule.ID}
	}
	if !*item.Existing && *item.Rule.ID == "" {
		return xdropValidateResult{NotFound: true}
	}
	return protocolError
}

func xdropUncertainCreate(entry store.ActionExecutionLog) bool {
	if strings.HasPrefix(entry.ErrorMessage, "create request:") {
		return false
	}
	if entry.StatusCode == nil {
		return true
	}
	code := *entry.StatusCode
	if code >= 400 && code < 500 {
		return false
	}
	if code == 200 || code == 201 {
		var response struct {
			ID string `json:"id"`
		}
		return json.Unmarshal([]byte(entry.ResponseBody), &response) != nil || response.ID == ""
	}
	return true
}

func xdropCreatePhase(phase string) bool {
	switch phase {
	case "on_detected", "confirmed", "type_upgrade", "updated":
		return true
	}
	return false
}

// Classify every observation before merging by the original body. A later
// rejected or unsent request cannot disprove an earlier uncertain commit.
func (e *Engine) xdropSyntheticBodies(ctx context.Context, k xdropRuleKey) ([]string, int, error) {
	c, cancel := context.WithTimeout(ctx, dbOperationTimeout)
	defer cancel()
	entries, err := e.store.ActionExecLog().ListByAttack(c, k.attack)
	if err != nil {
		return nil, 0, err
	}
	uncertain := map[string]bool{}
	var order []string
	count := 0
	for _, entry := range entries {
		if entry.ActionType != store.ActionTypeXDrop || entry.ActionID != k.action || entry.ConnectorID == nil || *entry.ConnectorID != k.connector || entry.ExternalRuleID != k.rule || entry.Status != "failed" || !xdropCreatePhase(entry.TriggerPhase) {
			continue
		}
		count++
		needsRecovery := xdropUncertainCreate(entry)
		if _, seen := uncertain[entry.RequestBody]; !seen {
			order = append(order, entry.RequestBody)
		}
		uncertain[entry.RequestBody] = uncertain[entry.RequestBody] || needsRecovery
	}
	var bodies []string
	for _, body := range order {
		if uncertain[body] {
			bodies = append(bodies, body)
		}
	}
	return bodies, count, nil
}

type xdropSyntheticPart struct {
	result xdropDeleteResult
	detail string
	skip   string
	source string // branch provenance; RemoteReleased alone also marks local closure
}

func (p xdropSyntheticPart) manualError() error {
	if p.result.Error != nil {
		return p.result.Error
	}
	if p.skip != "" {
		return fmt.Errorf("xdrop synthetic recovery %s: %s", p.skip, p.detail)
	}
	switch p.source {
	case "owned", "override", "not_found":
		return nil
	case "released":
		if p.result.RemoteReleased && p.result.HTTPStatus == http.StatusNoContent {
			return nil
		}
	}
	return fmt.Errorf("xdrop synthetic recovery not completed: %s", p.detail)
}

func (e *Engine) xdropUnrecoverable(k xdropRuleKey, name, reason string) {
	metrics.XDropReconcile.WithLabelValues("synthetic_unrecoverable").Inc()
	log.Printf("WARN action: xdrop synthetic failed-create unrecoverable rule=%s reason=%s", k.rule, reason)
	e.xdropLog(k, store.TriggerPhaseOnExpired, name, "success", "synthetic failed-create unrecoverable: "+reason, 0)
}

// The only nested lock order is S -> R. Ordinary recovery tries R once;
// terminal, late-create recovery waits with a finite independent budget.
func (e *Engine) xdropSyntheticReal(ctx context.Context, conn store.XDropConnector, k xdropRuleKey, wait, manual bool) xdropSyntheticPart {
	if wait {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 2*xdropTimeout(conn))
		defer cancel()
	}
	unlock, ok := e.lockXDrop(ctx, k, !wait)
	if !ok {
		return xdropSyntheticPart{skip: "busy", detail: "real rule lock unavailable"}
	}
	defer unlock()
	failure := func(err error) xdropSyntheticPart {
		return xdropSyntheticPart{result: xdropDeleteResult{Error: err}}
	}
	row, err := e.xdropReadRule(ctx, k)
	if err != nil {
		return failure(err)
	}
	owned := row != nil && (row.Status == "active" || row.Status == "delayed" || row.Status == "withdrawing" || row.Status == "failed")
	if row == nil {
		schedules, err := e.xdropSchedules(ctx)
		if err != nil {
			return failure(err)
		}
		for _, sa := range schedules {
			if sa.ActionType == "xdrop_unblock" && xdropKeyFromSchedule(sa) == k {
				owned = true
			}
		}
	}
	if owned {
		return xdropSyntheticPart{result: xdropDeleteResult{RemoteReleased: true}, source: "owned", detail: "synthetic claim owned by rule " + k.rule}
	}
	if !manual {
		c, cancel := context.WithTimeout(ctx, dbOperationTimeout)
		live, err := e.store.Attacks().LiveIDs(c, []int{k.attack})
		cancel()
		if err != nil {
			return failure(err)
		}
		if live[k.attack] || e.endingInFlight(k.attack) {
			return xdropSyntheticPart{skip: "skipped_live"}
		}
	}
	c, cancel := context.WithTimeout(ctx, dbOperationTimeout)
	current, err := e.store.XDropConnectors().Get(c, k.connector)
	cancel()
	if errors.Is(err, sql.ErrNoRows) || err == nil && (current == nil || !current.Enabled) {
		return xdropSyntheticPart{skip: "skipped_connector"}
	}
	if err != nil {
		return failure(err)
	}
	c, cancel = context.WithTimeout(ctx, dbOperationTimeout)
	overrides, err := e.store.ManualOverrides().ListByAttack(c, k.attack)
	cancel()
	if err != nil {
		return failure(err)
	}
	for _, override := range overrides {
		if override.ActionID == k.action && override.ConnectorID == k.connector && override.ExternalRuleID == k.rule {
			if manual {
				return xdropSyntheticPart{source: "override", detail: "real rule already force-removed"}
			}
			return xdropSyntheticPart{skip: "skipped_override"}
		}
	}
	if e.xdropStopped(ctx) {
		return xdropSyntheticPart{skip: "busy"}
	}
	result := deleteXDropClaim(*current, k)
	detail := "released rule " + k.rule
	if result.Error != nil {
		detail = result.Error.Error()
	}
	return xdropSyntheticPart{result: result, detail: detail, source: "released"}
}

func (e *Engine) recoverSyntheticXDrop(ctx context.Context, conn store.XDropConnector, k xdropRuleKey, bodies []string, wait, manual bool) xdropSyntheticPart {
	all := xdropSyntheticPart{result: xdropDeleteResult{RemoteReleased: true}}
	var details []string
	byRule := map[string]xdropSyntheticPart{}
	if manual && len(bodies) == 0 {
		log.Printf("WARN action: xdrop force-remove synthetic rule=%s no recoverable create evidence", k.rule)
	}
	for _, body := range bodies {
		var fields map[string]json.RawMessage
		var ref string
		if !json.Valid([]byte(body)) || json.Unmarshal([]byte(body), &fields) != nil || json.Unmarshal(fields["claim_ref"], &ref) != nil || ref != xdropClaimRef(k.attack, k.action) {
			if manual {
				log.Printf("WARN action: xdrop force-remove synthetic rule=%s no recoverable create evidence: invalid body or claim_ref", k.rule)
			} else {
				e.xdropUnrecoverable(k, conn.Name, "invalid body or claim_ref")
			}
			details = append(details, "unrecoverable body")
			continue
		}
		delete(fields, "claim_ref")
		item, _ := json.Marshal(fields)
		validated := validateXDropClaim(conn, item)
		part := xdropSyntheticPart{}
		switch {
		case validated.Error != nil:
			part.result.Error = validated.Error
			part.detail = validated.Error.Error()
		case validated.NotFound:
			part.result.RemoteReleased = true
			part.source = "not_found"
			part.detail = "identity not found; claim cannot be proven absent (rule identity may have been edited in XDrop)"
			if manual {
				log.Printf("WARN action: xdrop force-remove synthetic rule=%s %s", k.rule, part.detail)
			} else {
				metrics.XDropReconcile.WithLabelValues("synthetic_identity_not_found").Inc()
				log.Printf("INFO action: xdrop synthetic rule=%s %s", k.rule, part.detail)
				e.xdropLog(k, store.TriggerPhaseOnExpired, conn.Name, "success", part.detail, 0)
			}
		default:
			var seen bool
			part, seen = byRule[validated.RuleID]
			if !seen {
				realKey := k
				realKey.rule = validated.RuleID
				part = e.xdropSyntheticReal(ctx, conn, realKey, wait, manual)
				byRule[validated.RuleID] = part
			}
		}
		details = append(details, part.detail)
		if manual {
			part.result.Error = part.manualError()
		}
		// Failure is sticky across bodies, including a later successful
		// release or locally closed body. Never close S after a partial fail.
		if part.result.Error != nil {
			all.result.Error = part.result.Error
			all.result.RemoteReleased = false
		}
		if part.skip != "" {
			all.skip = part.skip
		}
	}
	all.detail = "synthetic failed-create closed locally"
	if len(details) > 0 {
		all.detail += "; " + strings.Join(details, "; ")
	}
	return all
}

func (e *Engine) xdropLateLeak(k xdropRuleKey, conn store.XDropConnector, detail string) {
	detail = redactXDropError(detail, conn.APIKey)
	metrics.XDropReconcile.WithLabelValues("late_create_leak").Inc()
	log.Printf("WARN action: xdrop late create leaked rule=%s detail=%s", k.rule, detail)
	e.xdropLog(k, store.TriggerPhaseOnExpired, conn.Name, "failed", "late create leaked: "+detail, 0)
}

func (e *Engine) xdropAfterCreate(conn store.XDropConnector, entry *store.ActionExecutionLog, body []byte) {
	if entry.Status == "failed" && !xdropUncertainCreate(*entry) {
		return
	}
	k := xdropRuleKey{entry.AttackID, entry.ActionID, conn.ID, entry.ExternalRuleID}
	ctx, cancel := context.WithTimeout(context.Background(), 2*xdropTimeout(conn))
	defer cancel()
	// Successful readback is the create commit point. Wait for synthetic
	// force removal to publish its override before taking R; both waits
	// share the same 2T budget and the only nested order remains S -> R.
	var unlockSynthetic func()
	if entry.Status != "failed" {
		syntheticKey := xdropRuleKey{entry.AttackID, entry.ActionID, conn.ID, syntheticFailedXDropRuleID(entry.AttackID, entry.ActionID)}
		var ok bool
		unlockSynthetic, ok = e.lockXDrop(ctx, syntheticKey, false)
		if !ok {
			e.xdropLateLeak(k, conn, "create readback lock unavailable")
			return
		}
	}
	unlock, ok := e.lockXDrop(ctx, k, false)
	if !ok {
		if unlockSynthetic != nil {
			unlockSynthetic()
		}
		e.xdropLateLeak(k, conn, "create readback lock unavailable")
		return
	}
	if unlockSynthetic != nil {
		defer unlockSynthetic()
	}
	defer unlock()
	row, err := e.xdropReadRule(ctx, k)
	if err != nil {
		e.xdropLateLeak(k, conn, "create readback failed")
		return
	}
	if row == nil {
		return
	}
	if row.Status != "withdrawn" {
		if entry.Status == "failed" {
			return
		}
		c, readCancel := context.WithTimeout(context.Background(), dbOperationTimeout)
		overrides, readErr := e.store.ManualOverrides().ListByAttack(c, k.attack)
		readCancel()
		if readErr != nil {
			log.Printf("WARN action: xdrop late create rule=%s manual override read failed: %s", k.rule, redactXDropError(readErr.Error(), conn.APIKey))
			return
		}
		overridden := false
		for _, override := range overrides {
			// Match the create-side suppression scope, including overrides
			// on S or another rule for this action and connector.
			if override.ActionID == k.action && override.ConnectorID == k.connector {
				overridden = true
				break
			}
		}
		if !overridden {
			return
		}
		c, writeCancel := context.WithTimeout(context.Background(), dbOperationTimeout)
		writeErr := e.store.XDropActiveRules().MarkWithdrawn(c, k.attack, k.action, k.connector, k.rule)
		writeCancel()
		if writeErr != nil {
			log.Printf("WARN action: xdrop late create rule=%s MarkWithdrawn failed: %s", k.rule, redactXDropError(writeErr.Error(), conn.APIKey))
		}
		// Operator intent won at readback. Release even if the terminal
		// write failed, using the existing late-create DELETE/log path.
	}
	if entry.Status == "failed" {
		manual := false
		c, readCancel := context.WithTimeout(context.Background(), dbOperationTimeout)
		overrides, readErr := e.store.ManualOverrides().ListByAttack(c, k.attack)
		readCancel()
		if readErr != nil {
			log.Printf("WARN action: xdrop late failed create rule=%s manual override read failed; using automatic recovery: %v", k.rule, readErr)
		} else {
			for _, override := range overrides {
				if override.AttackID == k.attack && override.ActionID == k.action && override.ConnectorID == k.connector && override.ExternalRuleID == k.rule {
					manual = true
					break
				}
			}
		}
		part := e.recoverSyntheticXDrop(context.Background(), conn, k, []string{string(body)}, true, manual)
		if part.result.Error != nil || part.skip != "" {
			if manual {
				recoveryError := ""
				if part.result.Error != nil {
					recoveryError = redactXDropError(part.result.Error.Error(), conn.APIKey)
				}
				log.Printf("WARN action: xdrop late failed create rule=%s manual recovery failed error=%s skip=%s", k.rule, recoveryError, part.skip)
			} else {
				e.xdropLateLeak(k, conn, part.detail+"; "+part.skip)
			}
		} else if !manual {
			e.xdropLog(k, store.TriggerPhaseOnExpired, conn.Name, "success", part.detail, 0)
		}
		return
	}
	result := deleteXDropClaim(conn, k)
	if !result.RemoteReleased {
		e.xdropLateLeak(k, conn, result.Error.Error())
		return
	}
	e.xdropLog(k, store.TriggerPhaseOnExpired, conn.Name, "success", "late create released", result.HTTPStatus)
}

type xdropRuleLock struct {
	held chan struct{}
	refs int // holder plus waiters, protected by xdropMu
}

type xdropRetry struct {
	failures    int
	nextAttempt time.Time
	connector   int
}

func (e *Engine) xdropStopped(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	e.xdropMu.Lock()
	defer e.xdropMu.Unlock()
	return e.xdropContext != nil && e.xdropContext.Err() != nil
}

func (e *Engine) lockXDrop(ctx context.Context, k xdropRuleKey, try bool) (func(), bool) {
	if e.xdropStopped(ctx) {
		return nil, false
	}
	key := k.String()
	e.xdropMu.Lock()
	if e.xdropLocks == nil {
		e.xdropLocks = make(map[string]*xdropRuleLock)
	}
	l := e.xdropLocks[key]
	if l == nil {
		l = &xdropRuleLock{held: make(chan struct{}, 1)}
		e.xdropLocks[key] = l
	}
	l.refs++
	var stopped <-chan struct{}
	if e.xdropContext != nil {
		stopped = e.xdropContext.Done()
	}
	e.xdropMu.Unlock()
	dropRef := func() {
		e.xdropMu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(e.xdropLocks, key)
		}
		e.xdropMu.Unlock()
	}
	if try {
		select {
		case l.held <- struct{}{}:
		default:
			dropRef()
			return nil, false
		}
	} else {
		select {
		case l.held <- struct{}{}:
		case <-ctx.Done():
			dropRef()
			return nil, false
		case <-stopped:
			dropRef()
			return nil, false
		}
	}
	unlock := func() { <-l.held; dropRef() }
	if e.xdropStopped(ctx) {
		unlock()
		return nil, false
	}
	return unlock, true
}

func (e *Engine) xdropObserveConnector(id int, enabled bool) {
	e.xdropMu.Lock()
	defer e.xdropMu.Unlock()
	if e.xdropEnabled == nil {
		e.xdropEnabled = make(map[int]bool)
	}
	if previous, seen := e.xdropEnabled[id]; seen && !previous && enabled {
		for key, r := range e.xdropRetries {
			if r.connector == id {
				delete(e.xdropRetries, key)
			}
		}
	}
	e.xdropEnabled[id] = enabled
}

func (e *Engine) xdropBackoff(k xdropRuleKey) bool {
	return e.xdropBackoffAt(k, time.Now())
}

func (e *Engine) xdropBackoffAt(k xdropRuleKey, at time.Time) bool {
	e.xdropMu.Lock()
	defer e.xdropMu.Unlock()
	return at.Before(e.xdropRetries[k.String()].nextAttempt)
}

func (e *Engine) xdropAttemptFinished(k xdropRuleKey, success bool, started time.Time) xdropRetry {
	e.xdropMu.Lock()
	defer e.xdropMu.Unlock()
	key := k.String()
	if success {
		delete(e.xdropRetries, key)
		return xdropRetry{}
	}
	if e.xdropRetries == nil {
		e.xdropRetries = make(map[string]xdropRetry)
	}
	r := e.xdropRetries[key]
	r.failures++
	r.connector = k.connector
	interval := e.xdropInterval
	if interval <= 0 {
		interval = xdropReconcileInterval
	}
	r.nextAttempt = started.Add(interval * time.Duration(1<<min(r.failures-1, 3)))
	e.xdropRetries[key] = r
	return r
}

func xdropStateWriteFailure(op string, err error) {
	metrics.StateWriteFailures.WithLabelValues(op).Inc()
	metrics.XDropReconcile.WithLabelValues("state_write_error").Inc()
	log.Printf("WARN action: xdrop state write op=%s error=%v", op, err)
}

func xdropWrite(op string, write func(context.Context) error) error {
	var err error
	for n := 0; n < 3; n++ {
		if n > 0 {
			time.Sleep(time.Duration(n) * 100 * time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), dbOperationTimeout)
		err = write(ctx)
		cancel()
		if err == nil {
			return nil
		}
	}
	xdropStateWriteFailure(op, err)
	return err
}

func (e *Engine) xdropReadRule(ctx context.Context, k xdropRuleKey) (*store.XDropActiveRule, error) {
	c, cancel := context.WithTimeout(ctx, dbOperationTimeout)
	defer cancel()
	rows, err := e.store.XDropActiveRules().ListByAttack(c, k.attack)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if xdropKeyFromSchedule(xdropScheduleForRule(r)) == k {
			return &r, nil
		}
	}
	return nil, nil
}

func (e *Engine) xdropSchedules(ctx context.Context) ([]store.ScheduledAction, error) {
	c, cancel := context.WithTimeout(ctx, dbOperationTimeout)
	defer cancel()
	pending, err := e.store.ScheduledActions().ListPending(c)
	if err != nil {
		return nil, err
	}
	executing, err := e.store.ScheduledActions().ListExecuting(c)
	if err != nil {
		return nil, err
	}
	return append(pending, executing...), nil
}

func (e *Engine) xdropFinishSchedules(schedules []store.ScheduledAction, success bool, detail string) error {
	var last error
	for _, sa := range schedules {
		err := xdropWrite("xdrop_schedule_finish", func(ctx context.Context) error {
			if success {
				return e.store.ScheduledActions().Complete(ctx, sa.ID)
			}
			return e.store.ScheduledActions().Fail(ctx, sa.ID, detail)
		})
		if err != nil {
			last = err
			continue
		}
		e.delayMu.Lock()
		delete(e.pendingDelay, delayKey(sa.AttackID, sa.ActionID, sa.ConnectorID, sa.ExternalRuleID))
		e.delayMu.Unlock()
	}
	return last
}

func (e *Engine) xdropLog(k xdropRuleKey, phase, name, status, detail string, code int) {
	entry := &store.ActionExecutionLog{AttackID: k.attack, ActionID: k.action, ActionType: store.ActionTypeXDrop, ConnectorID: &k.connector, ConnectorName: name, TriggerPhase: phase, ExternalRuleID: k.rule, Status: status, ErrorMessage: detail, ExecutedAt: time.Now()}
	if code > 0 {
		entry.StatusCode = &code
	}
	if _, err := writeExecLog(e.store, entry); err != nil {
		xdropStateWriteFailure("xdrop_exec_log", err)
	}
}

// Every automatic entry uses this lock, including schedule creation below.
func (e *Engine) withdrawXDropRule(ctx context.Context, sa store.ScheduledAction, origin, phase string) string {
	unlock, ok := e.lockXDrop(ctx, xdropKeyFromSchedule(sa), false)
	if !ok {
		return "busy"
	}
	defer unlock()
	return e.withdrawXDropLocked(ctx, sa, origin, phase, time.Time{})
}

func (e *Engine) withdrawXDropLocked(ctx context.Context, sa store.ScheduledAction, origin, phase string, roundStart time.Time) string {
	k := xdropKeyFromSchedule(sa)
	row, err := e.xdropReadRule(ctx, k)
	rowID := 0
	if row != nil {
		rowID = row.ID
	}
	sweep := origin == "ended-sweep" || origin == "startup-cleanup"
	claimed := false
	outcome := func(value string, err error) string {
		label := value
		if label == "skipped_claimed" {
			label = "busy"
		}
		metrics.XDropReconcile.WithLabelValues(label).Inc()
		if sweep && !claimed {
			v := value
			if v == "list_error" || v == "state_write_error" {
				v = "failed"
			}
			if v == "backoff" || v == "busy" {
				v = "skipped_claimed"
			}
			if origin == "ended-sweep" {
				endedOutcome("xdrop", k.attack, rowID, v, err)
			} else {
				startupOutcome("xdrop", v, rowID, nil, err)
			}
		}
		log.Printf("INFO action: xdrop withdraw origin=%s row_id=%d outcome=%s error=%v", origin, rowID, value, err)
		return value
	}
	if err != nil {
		return outcome("list_error", err)
	}
	// Ordinary entries never invent an external claim from an absent row.
	if row == nil && sa.ID == 0 {
		e.xdropAttemptFinished(k, true, time.Time{})
		return "absent"
	}
	schedules, err := e.xdropSchedules(ctx)
	if err != nil {
		return outcome("list_error", err)
	}
	var related []store.ScheduledAction
	foundSchedule := false
	for _, current := range schedules {
		if current.ActionType != "xdrop_unblock" || xdropKeyFromSchedule(current) != k {
			continue
		}
		related = append(related, current)
		if current.ID == sa.ID {
			foundSchedule = true
			sa = current
		}
	}
	// A delayed/recovered worker may have waited behind a successful owner.
	// Validate both schedule identity and business key while holding this lock.
	if row == nil && !foundSchedule {
		e.xdropAttemptFinished(k, true, time.Time{})
		return "absent"
	}
	if row != nil && row.Status == "withdrawn" {
		if err := e.xdropFinishSchedules(related, true, ""); err != nil {
			return outcome("state_write_error", err)
		}
		e.xdropAttemptFinished(k, true, time.Time{})
		return "withdrawn"
	}
	if sweep && row != nil && row.Status != "active" {
		return outcome("skipped_claimed", nil)
	}
	if row != nil {
		switch row.Status {
		case "active", "delayed", "failed":
		case "withdrawing":
			if origin != "recovered" && origin != "reconcile" {
				return outcome("skipped_claimed", nil)
			}
		default:
			return "absent"
		}
	}
	c, cancel := context.WithTimeout(ctx, dbOperationTimeout)
	conn, err := e.store.XDropConnectors().Get(c, k.connector)
	cancel()
	if errors.Is(err, sql.ErrNoRows) {
		return outcome("skipped_connector", nil)
	}
	if err != nil {
		return outcome("list_error", err)
	}
	if conn == nil {
		return outcome("skipped_connector", nil)
	}
	e.xdropObserveConnector(k.connector, conn.Enabled)
	if !conn.Enabled {
		return outcome("skipped_connector", nil)
	}
	c, cancel = context.WithTimeout(ctx, dbOperationTimeout)
	overrides, err := e.store.ManualOverrides().ListByAttack(c, k.attack)
	cancel()
	if err != nil {
		return outcome("list_error", err)
	}
	for _, o := range overrides {
		if o.ActionID == k.action && o.ConnectorID == k.connector && o.ExternalRuleID == k.rule {
			return outcome("skipped_override", nil)
		}
	}
	if origin == "reconcile" {
		c, cancel = context.WithTimeout(ctx, dbOperationTimeout)
		live, err := e.store.Attacks().LiveIDs(c, []int{k.attack})
		cancel()
		if err != nil {
			return outcome("list_error", err)
		}
		if live[k.attack] || e.endingInFlight(k.attack) {
			return outcome("skipped_live", nil)
		}
	}
	if sweep && len(related) > 0 {
		return outcome("skipped_scheduled", nil)
	}
	for _, current := range related {
		if current.Status == "pending" && time.Now().Before(current.ScheduledFor) {
			return outcome("skipped_scheduled", nil)
		}
	}
	retryAt := time.Now()
	if origin == "reconcile" {
		e.xdropMu.Lock()
		interval := e.xdropInterval
		e.xdropMu.Unlock()
		if interval <= 0 {
			interval = xdropReconcileInterval
		}
		// Only discrete reconcile ticks need slack for dispatch/query latency;
		// event entries have no such quantization and retain strict eligibility.
		retryAt = roundStart.Add(interval / 10)
	}
	if e.xdropBackoffAt(k, retryAt) {
		return outcome("backoff", nil)
	}
	if e.xdropStopped(ctx) {
		return "cancelled"
	}
	// Backoff starts with this locked attempt, never with the HTTP response.
	attemptStarted := time.Now()
	synthetic := isSyntheticFailedXDropRuleID(k.rule)
	var recovered xdropSyntheticPart
	if synthetic {
		bodies, count, err := e.xdropSyntheticBodies(ctx, k)
		if err != nil {
			return outcome("list_error", err)
		}
		if count == 0 {
			e.xdropUnrecoverable(k, conn.Name, "no create execution logs")
		}
		recovered = e.recoverSyntheticXDrop(ctx, *conn, k, bodies, false, false)
		if recovered.result.Error == nil && recovered.skip != "" {
			return outcome(recovered.skip, nil)
		}
	}
	if row != nil && row.Status != "withdrawing" {
		c, cancel = context.WithTimeout(context.Background(), dbOperationTimeout)
		var ok bool
		if origin == "ended-sweep" {
			ok, err = e.store.XDropActiveRules().ClaimActive(c, k.attack, k.action, k.connector, k.rule)
		} else {
			ok, err = e.store.XDropActiveRules().MarkWithdrawing(c, k.attack, k.action, k.connector, k.rule)
		}
		cancel()
		if err != nil {
			xdropStateWriteFailure("xdrop_claim", err)
			e.xdropAttemptFinished(k, false, attemptStarted)
			return outcome("state_write_error", err)
		}
		if !ok {
			return outcome("skipped_claimed", nil)
		}
	}
	claimed = true
	metrics.XDropReconcile.WithLabelValues("claimed").Inc()
	if origin == "ended-sweep" {
		endedOutcome("xdrop", k.attack, rowID, "dispatched", nil)
	}
	if origin == "startup-cleanup" {
		startupOutcome("xdrop", "dispatched", rowID, nil, nil)
	}
	if e.xdropStopped(ctx) {
		return "cancelled"
	}
	result := recovered.result
	if !synthetic {
		result = deleteXDropClaim(*conn, k)
	}
	detail := ""
	if result.Error != nil {
		detail = result.Error.Error()
	}
	if synthetic {
		detail = recovered.detail
	}
	writeErr := error(nil)
	if row != nil {
		op, target := "xdrop_mark_failed", "failed"
		if result.RemoteReleased {
			op, target = "xdrop_mark_withdrawn", "withdrawn"
		}
		writeErr = xdropWrite(op, func(c context.Context) error {
			current, err := e.xdropReadRule(c, k)
			if err != nil {
				return err
			}
			if current == nil {
				return fmt.Errorf("xdrop row disappeared during withdrawal")
			}
			if current.Status == target {
				return nil
			}
			if current.Status != "withdrawing" {
				return fmt.Errorf("xdrop terminal write requires withdrawing, got %s", current.Status)
			}
			if result.RemoteReleased {
				err = e.store.XDropActiveRules().MarkWithdrawn(c, k.attack, k.action, k.connector, k.rule)
			} else {
				err = e.store.XDropActiveRules().MarkFailed(c, k.attack, k.action, k.connector, k.rule, detail)
			}
			if err != nil {
				return err
			}
			current, err = e.xdropReadRule(c, k)
			if err != nil {
				return err
			}
			if current == nil || current.Status != target {
				return fmt.Errorf("xdrop terminal write not confirmed")
			}
			return nil
		})
	}
	// A failed no-row legacy schedule must remain executing so reconcile can
	// find it again. There is no rule row to carry its retry otherwise.
	if writeErr == nil && (row != nil || result.RemoteReleased) {
		writeErr = e.xdropFinishSchedules(related, result.RemoteReleased, detail)
	}
	if writeErr != nil {
		detail += fmt.Sprintf("; remote_released=%t; state persistence failed: %v", result.RemoteReleased, writeErr)
	}
	success := result.RemoteReleased && writeErr == nil
	retry := e.xdropAttemptFinished(k, success, attemptStarted)
	status, value := "failed", "failed"
	if success {
		status, value = "success", "withdrawn"
	}
	if synthetic {
		phase = store.TriggerPhaseOnExpired
	}
	e.xdropLog(k, phase, conn.Name, status, detail, result.HTTPStatus)
	level := "INFO"
	if !success {
		level = "WARN"
	}
	log.Printf("%s action: xdrop withdraw origin=%s row_id=%d outcome=%s attempt=%d next_retry_at=%s remote_released=%t detail=%s", level, origin, rowID, value, retry.failures, retry.nextAttempt.Format(time.RFC3339Nano), result.RemoteReleased, detail)
	return outcome(value, writeErr)
}

// Persisting a delay and advertising delayed state form a short critical
// section. The timer never holds the row lock; execution acquires it anew.
const xdropScheduleFailure = "xDrop delayed unblock could not be scheduled; reconcile will withdraw"

func (e *Engine) scheduleXDrop(ctx context.Context, sa store.ScheduledAction, phase, response string) (bool, error) {
	k := xdropKeyFromSchedule(sa)
	unlock, ok := e.lockXDrop(ctx, k, false)
	if !ok {
		return false, ctx.Err()
	}
	defer unlock()
	queryFailure := func(name string) (bool, error) {
		metrics.XDropReconcile.WithLabelValues("list_error").Inc()
		log.Printf("WARN action: xdrop delayed unblock list_error: %s", xdropScheduleFailure)
		e.xdropLog(k, phase, name, "failed", xdropScheduleFailure, 0)
		return false, errors.New(xdropScheduleFailure)
	}
	r, err := e.xdropReadRule(ctx, k)
	if err != nil {
		return queryFailure("")
	}
	if r == nil || r.Status == "withdrawn" || r.Status == "withdrawing" {
		return false, nil
	}
	conn, err := e.store.XDropConnectors().Get(ctx, k.connector)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return queryFailure("")
	}
	if conn == nil || !conn.Enabled {
		return false, nil
	}
	overrides, err := e.store.ManualOverrides().ListByAttack(ctx, k.attack)
	if err != nil {
		return queryFailure(conn.Name)
	}
	for _, o := range overrides {
		if o.ActionID == k.action && o.ConnectorID == k.connector && o.ExternalRuleID == k.rule {
			return false, nil
		}
	}
	schedules, err := e.xdropSchedules(ctx)
	if err != nil {
		return queryFailure(conn.Name)
	}
	for _, current := range schedules {
		if current.ActionType == "xdrop_unblock" && xdropKeyFromSchedule(current) == k {
			return true, nil // the key already has a durable schedule
		}
	}
	if e.xdropBackoff(k) || e.xdropStopped(ctx) {
		return false, nil
	}
	id, timerCtx, err := e.ScheduleDelay(ctx, sa.ActionType, k.attack, k.action, k.connector, k.rule, sa.ScheduledFor)
	if err != nil {
		detail := fmt.Sprintf("schedule persist failed: %v", err)
		// No delay or HTTP side effect exists yet. Record this scheduling
		// failure once, then release the child so ended sweep can take the
		// remaining active row. HTTP terminal writes retain xdropWrite's
		// three independent attempts and confirmation below the row lock.
		c, cancel := context.WithTimeout(context.Background(), dbOperationTimeout)
		writeErr := e.store.XDropActiveRules().MarkFailed(c, k.attack, k.action, k.connector, k.rule, detail)
		cancel()
		if writeErr != nil {
			xdropStateWriteFailure("xdrop_mark_failed", writeErr)
		}
		e.xdropLog(k, phase, conn.Name, "failed", detail, 0)
		return false, errors.New(xdropScheduleFailure)
	}
	sa.ID = id
	delay := time.Until(sa.ScheduledFor)
	if err := e.store.XDropActiveRules().MarkDelayed(ctx, k.attack, k.action, k.connector, k.rule, int(delay/time.Minute)); err != nil {
		log.Printf("WARN action: xdrop mark delayed: %v", err)
	}
	entry := &store.ActionExecutionLog{AttackID: k.attack, ActionID: k.action, ActionType: "xdrop", TriggerPhase: phase, ResponseName: response, ConnectorName: conn.Name, ConnectorID: &k.connector, ExternalRuleID: k.rule, Status: "scheduled", ErrorMessage: fmt.Sprintf("delayed unblock in %v", delay), ScheduledFor: &sa.ScheduledFor, ExecutedAt: time.Now()}
	if _, err := writeExecLog(e.store, entry); err != nil {
		xdropStateWriteFailure("xdrop_exec_log", err)
	}
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timerCtx.Done():
			return
		case <-timer.C:
		}
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if !e.MarkExecutingDelay(c, id) {
			return
		}
		e.withdrawXDropRule(c, sa, "delayed", phase)
	}()
	return true, nil
}
