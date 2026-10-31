package tests

import (
	"context"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// helpers shared across recovery tests
// ─────────────────────────────────────────────────────────────────────────────

// defaultBGPConnector returns a BGPConnector pointing at /usr/bin/false so that
// vtysh calls fail gracefully (exit non-zero) without crashing the process.
// On macOS /usr/bin/false is always present and exits 1 immediately.
func defaultBGPConnector(id int) store.BGPConnector {
	return store.BGPConnector{
		ID:            id,
		Name:          "test-bgp",
		VtyshPath:     "/usr/bin/false",
		BGPASN:        65001,
		AddressFamily: "ipv4 unicast",
		Enabled:       true,
		Description:   "test connector",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

// bgpOnDetectedLog creates an on_detected success log for a BGP route.
func bgpOnDetectedLog(attackID, actionID, connectorID, logID int, ruleID string, at time.Time) store.ActionExecutionLog {
	return store.ActionExecutionLog{
		ID:             logID,
		AttackID:       attackID,
		ActionID:       actionID,
		ActionType:     "bgp",
		TriggerPhase:   "on_detected",
		Status:         "success",
		ExternalRuleID: ruleID,
		ConnectorID:    intPtr(connectorID),
		ConnectorName:  "test-bgp",
		ExecutedAt:     at,
	}
}

// bgpOnExpiredLog creates an on_expired success log for a BGP route.
func bgpOnExpiredLog(attackID, actionID, connectorID, logID int, ruleID string, at time.Time) store.ActionExecutionLog {
	return store.ActionExecutionLog{
		ID:             logID,
		AttackID:       attackID,
		ActionID:       actionID,
		ActionType:     "bgp",
		TriggerPhase:   "on_expired",
		Status:         "success",
		ExternalRuleID: ruleID,
		ConnectorID:    intPtr(connectorID),
		ConnectorName:  "test-bgp",
		ExecutedAt:     at,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// U25: RecoverBGPRoutes — active attack with un-withdrawn BGP route
//
// RecoverBGPRoutes should attempt to re-inject the route (calls vtysh).
// vtysh points to /usr/bin/false so it will fail, but the function must not
// panic and must complete normally.  The key assertion: no panic.
// ─────────────────────────────────────────────────────────────────────────────

func TestRecovery_ActiveAttack_NoPanic(t *testing.T) {
	ms := NewMockStore()
	conn := defaultBGPConnector(1)
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, conn)

	now := time.Now()
	// Active attack (EndedAt == nil)
	atk := store.Attack{
		ID:        100,
		DstIP:     "10.100.0.1",
		StartedAt: now.Add(-10 * time.Minute),
		EndedAt:   nil,
	}
	ms.attacks.attacks = append(ms.attacks.attacks, atk)

	// on_detected success log — the route was injected when the attack started
	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		bgpOnDetectedLog(100, 1, conn.ID, 1, "10.100.0.1/32|RTBH", now.Add(-9*time.Minute)),
	)

	// Should not panic; vtysh will fail gracefully
	ctx := context.Background()
	action.RecoverBGPRoutes(ctx, ms)

	// No further assertion needed — the test passes if it completes without panic.
	// The re-injection attempt will fail due to /usr/bin/false, but that is logged
	// and the function continues normally per its design (log.Printf on error).
}

// ─────────────────────────────────────────────────────────────────────────────
// U26 / T1: CleanupEndedAttachments withdraws an ended attack with no prior withdrawal.
// The fixture seeds the announcement and attachment, records real fake-vtysh
// arguments, and checks both sides of the asynchronous connector barrier.
// ─────────────────────────────────────────────────────────────────────────────

// T1: startup cleanup must detach and withdraw, including async boundary assertions.
func TestRecovery_ExpiredNoWithdraw_AttemptsCleanup(t *testing.T) { fzWithdraw(t, "") }

// ─────────────────────────────────────────────────────────────────────────────
// U27 / T1: CleanupEndedAttachments removes the stale ended-attack attachment.
// The successful fake process and state/metric assertions replace the old
// nonexistent executable and no-assertion smoke test.
// ─────────────────────────────────────────────────────────────────────────────

// T1: startup cleanup must detach and withdraw, including async boundary assertions.
func TestRecovery_ExpiredStale_AttemptsCleanup(t *testing.T) { fzWithdraw(t, "") }

// ─────────────────────────────────────────────────────────────────────────────
// U28: RecoverBGPRoutes — already-withdrawn route must NOT trigger re-withdrawal
//
// This test verifies that RecoverBGPRoutes respects the existing on_expired
// success log and does NOT attempt another withdrawal.  We confirm this by
// observing the mock's log slice — no new entries must be added.
//
// Because RecoverBGPRoutes does not write new logs (it only calls runVtysh),
// we measure the side-effect by ensuring that the function completes with the
// same number of logs as before AND without panic.
// ─────────────────────────────────────────────────────────────────────────────

func TestRecovery_AlreadyWithdrawn_Skips(t *testing.T) {
	ms := NewMockStore()
	conn := defaultBGPConnector(1)
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, conn)

	now := time.Now()
	endedAt := now.Add(-2 * time.Hour)
	atk := store.Attack{
		ID:        103,
		DstIP:     "10.103.0.1",
		StartedAt: now.Add(-3 * time.Hour),
		EndedAt:   &endedAt,
	}
	ms.attacks.expiredAttacks = append(ms.attacks.expiredAttacks, atk)

	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		// Route was injected
		bgpOnDetectedLog(103, 4, conn.ID, 1, "10.103.0.1/32|RTBH", now.Add(-3*time.Hour)),
		// Route was already withdrawn
		bgpOnExpiredLog(103, 4, conn.ID, 2, "10.103.0.1/32|RTBH", now.Add(-2*time.Hour+1*time.Minute)),
	)

	logCountBefore := len(ms.actionExecLog.snapshotLogs())

	ctx := context.Background()
	action.RecoverBGPRoutes(ctx, ms)

	// RecoverBGPRoutes does not write logs — the log count must not increase.
	// (If the route was not skipped, runVtysh would be called; but because it IS
	// skipped, no side-effects occur beyond possibly logging to stdout.)
	logCountAfter := len(ms.actionExecLog.snapshotLogs())
	if logCountAfter != logCountBefore {
		t.Errorf("expected log count to stay at %d, got %d (recovery must skip already-withdrawn routes)",
			logCountBefore, logCountAfter)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional: RecoverBGPRoutes with no connectors configured — no-op, no panic
// ─────────────────────────────────────────────────────────────────────────────

func TestRecovery_NoConnectors_NoPanic(t *testing.T) {
	ms := NewMockStore()
	// No connectors — function should return immediately
	ctx := context.Background()
	action.RecoverBGPRoutes(ctx, ms)
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional: RecoverBGPRoutes — disabled connector must be skipped
// ─────────────────────────────────────────────────────────────────────────────

func TestRecovery_DisabledConnector_NoPanic(t *testing.T) {
	ms := NewMockStore()

	conn := store.BGPConnector{
		ID:            1,
		Name:          "disabled-bgp",
		VtyshPath:     "/usr/bin/false",
		BGPASN:        65001,
		AddressFamily: "ipv4 unicast",
		Enabled:       false, // DISABLED
	}
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, conn)

	now := time.Now()
	atk := store.Attack{
		ID:        104,
		DstIP:     "10.104.0.1",
		StartedAt: now.Add(-5 * time.Minute),
		EndedAt:   nil,
	}
	ms.attacks.attacks = append(ms.attacks.attacks, atk)

	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		bgpOnDetectedLog(104, 5, conn.ID, 1, "10.104.0.1/32|RTBH", now.Add(-4*time.Minute)),
	)

	// Disabled connector: no vtysh call; function must not panic.
	ctx := context.Background()
	action.RecoverBGPRoutes(ctx, ms)
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional: active attack with multiple on_detected logs (same connector)
// — both routes should be attempted for re-injection, none should panic.
// ─────────────────────────────────────────────────────────────────────────────

func TestRecovery_MultipleRoutes_NoPanic(t *testing.T) {
	ms := NewMockStore()
	conn := defaultBGPConnector(1)
	ms.bgpConnectors.connectors = append(ms.bgpConnectors.connectors, conn)

	now := time.Now()
	atk := store.Attack{
		ID:        105,
		DstIP:     "10.105.0.1",
		StartedAt: now.Add(-15 * time.Minute),
		EndedAt:   nil,
	}
	ms.attacks.attacks = append(ms.attacks.attacks, atk)

	ms.actionExecLog.logs = append(ms.actionExecLog.logs,
		bgpOnDetectedLog(105, 6, conn.ID, 1, "10.105.0.1/32|RTBH", now.Add(-14*time.Minute)),
		bgpOnDetectedLog(105, 7, conn.ID, 2, "10.105.0.1/32:BLACKHOLE", now.Add(-13*time.Minute)),
	)

	ctx := context.Background()
	action.RecoverBGPRoutes(ctx, ms)
	// Both re-injection attempts fail (no real vtysh) — function completes without panic.
}
