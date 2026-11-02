package action

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

const shellWaitDelay = 2 * time.Second

// executeShell executes a shell action using the configured ShellConnector.
func executeShell(
	ctx context.Context,
	s store.Store,
	action store.ResponseAction,
	attack *store.Attack,
	eventType string,
	prefixStr string,
	responseName string,
	triggerPhase string,
	attackDBID int,
	fa *FlowAnalysis,
) (*store.ActionExecutionLog, error) {
	skipLog := func(reason, message string) *store.ActionExecutionLog {
		row := &store.ActionExecutionLog{
			AttackID:     attackDBID,
			ActionID:     action.ID,
			ResponseName: responseName,
			ActionType:   "shell",
			TriggerPhase: triggerPhase,
			Status:       "skipped",
			ErrorMessage: message,
			ExecutedAt:   time.Now(),
		}
		recordSkip(row, reason)
		return row
	}
	if action.ShellConnectorID == nil {
		log.Printf("action: shell action %d skipped: no shell_connector_id", action.ID)
		return skipLog(SkipReasonNoConnector, "shell action has no shell_connector_id"), nil
	}

	connector, err := s.ShellConnectors().Get(ctx, *action.ShellConnectorID)
	if err != nil {
		err = fmt.Errorf("get shell connector %d: %w", *action.ShellConnectorID, err)
		return skipLog(SkipReasonConnectorLookupFailed, err.Error()), err
	}
	if !connector.Enabled {
		execLog := &store.ActionExecutionLog{
			AttackID:      attackDBID,
			ActionID:      action.ID,
			ResponseName:  responseName,
			ActionType:    "shell",
			ConnectorName: connector.Name,
			TriggerPhase:  triggerPhase,
			Status:        "skipped",
			ErrorMessage:  "shell connector is disabled",
			ExecutedAt:    time.Now(),
		}
		recordSkip(execLog, SkipReasonConnectorDisabled)
		return execLog, nil
	}

	// Build arguments: connector default_args + action shell_extra_args
	// Both support {var} expansion
	var args []string

	for _, tok := range splitArgs(connector.DefaultArgs) {
		args = append(args, expandParams(tok, attack, eventType, prefixStr, fa))
	}

	for _, tok := range splitArgs(action.ShellExtraArgs) {
		args = append(args, expandParams(tok, attack, eventType, prefixStr, fa))
	}

	// Set up command with timeout
	timeout := 30 * time.Second
	if connector.TimeoutMs > 0 {
		timeout = time.Duration(connector.TimeoutMs) * time.Millisecond
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, connector.Command, args...)
	cmd.WaitDelay = shellWaitDelay

	// If pass_stdin, pipe JSON payload via stdin
	if connector.PassStdin {
		payload := map[string]any{
			"event":        eventType,
			"attack_id":    attack.ID,
			"dst_ip":       attack.DstIP,
			"prefix":       prefixStr,
			"attack_type":  attack.AttackType,
			"severity":     attack.Severity,
			"peak_pps":     attack.PeakPPS,
			"peak_bps":     attack.PeakBPS,
			"reason_codes": attack.ReasonCodes,
			"node_sources": attack.NodeSources,
			"started_at":   attack.StartedAt.Format(time.RFC3339),
		}
		if attack.EndedAt != nil {
			payload["ended_at"] = attack.EndedAt.Format(time.RFC3339)
		}
		stdinData, _ := json.Marshal(payload)
		cmd.Stdin = bytes.NewReader(stdinData)
	}

	// Capture stdout + stderr
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	execLog := &store.ActionExecutionLog{
		AttackID:      attackDBID,
		ActionID:      action.ID,
		ResponseName:  responseName,
		ActionType:    "shell",
		ConnectorName: connector.Name,
		TriggerPhase:  triggerPhase,
		RequestBody:   fmt.Sprintf("%s %s", connector.Command, strings.Join(args, " ")),
		ExecutedAt:    time.Now(),
	}

	start := time.Now()
	deadline, _ := cmdCtx.Deadline()
	budget := deadline.Sub(start)
	err = cmd.Run()
	execLog.DurationMs = int(time.Since(start).Milliseconds())

	// Truncate output to 1KB
	output := truncateStr(outBuf.String(), 1024)
	execLog.ResponseBody = output

	if cmdCtx.Err() != nil {
		execLog.Status = "timeout"
		execLog.ErrorMessage = fmt.Sprintf("command timed out after %dms", budget.Round(time.Millisecond).Milliseconds())
		return execLog, cmdCtx.Err()
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		execLog.ErrorMessage = "background process held output; output truncated"
	} else if err != nil {
		execLog.Status = "failed"
		execLog.ErrorMessage = err.Error()
		return execLog, err
	}

	exitCode := cmd.ProcessState.ExitCode()
	execLog.StatusCode = &exitCode
	if exitCode != 0 {
		execLog.Status = "failed"
		execLog.ErrorMessage = fmt.Sprintf("exit code %d", exitCode)
		return execLog, fmt.Errorf("shell command exited with code %d: %s", exitCode, output)
	}

	execLog.Status = "success"
	return execLog, nil
}

// splitArgs splits a space-separated argument string into individual args.
// Respects simple quoting (double quotes).
func splitArgs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	var args []string
	var current strings.Builder
	inQuote := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
		case ch == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}
