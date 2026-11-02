package tests

import (
	"context"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// insertManualOverride is a helper that records a manual override into the
// new action_manual_overrides index (v1.2 PR-2) + writes the corresponding
// audit log entry (v1.1 behavior, retained for downstream audits).
func insertManualOverride(t *testing.T, ms *MockStore, attackID, actionID, connectorID int, ruleID string) {
	t.Helper()
	// v1.2 PR-2: index table — authoritative for ManualOverrides.Exists lookups
	if _, err := ms.manualOverrides.Create(context.Background(), &store.ActionManualOverride{
		AttackID:       attackID,
		ActionID:       actionID,
		ConnectorID:    connectorID,
		ExternalRuleID: ruleID,
	}); err != nil {
		t.Fatalf("insertManualOverride index: %v", err)
	}
	// Audit log — kept for backward compat and non-lookup consumers
	cid := connectorID
	logEntry := &store.ActionExecutionLog{
		AttackID:       attackID,
		ActionID:       actionID,
		TriggerPhase:   "manual_override",
		Status:         "success",
		ExternalRuleID: ruleID,
		ConnectorID:    &cid,
		ExecutedAt:     time.Now(),
	}
	if _, err := ms.actionExecLogRepo.Create(context.Background(), logEntry); err != nil {
		t.Fatalf("insertManualOverride log: %v", err)
	}
}

// U31: A manual_override success log causes ManualOverrides.Exists to return true.
func TestManualOverride_SuppressesOnExpired(t *testing.T) {
	ms := NewMockStore()

	insertManualOverride(t, ms, 1, 2, 3, "r1")

	got, err := ms.ManualOverrides().Exists(context.Background(), 1, 2, 3, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Error("U31: ManualOverrides.Exists should return true when manual_override success log exists")
	}
}

// U32: A manual_override for attack 1 does NOT suppress actions for attack 2.
func TestManualOverride_DoesNotAffectOtherAttacks(t *testing.T) {
	ms := NewMockStore()

	// Override recorded for attack 1.
	insertManualOverride(t, ms, 1, 2, 3, "r1")

	// Query for attack 2 — should return false.
	got, err := ms.ManualOverrides().Exists(context.Background(), 2, 2, 3, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Error("U32: ManualOverrides.Exists should return false for a different attackID")
	}
}

// U33: Manual override is per-artifact (connectorID + externalRuleID combination).
func TestManualOverride_PerArtifactSuppression(t *testing.T) {
	ms := NewMockStore()

	// Override only for connector 3 / rule "r1".
	insertManualOverride(t, ms, 1, 2, 3, "r1")

	t.Run("matching artifact returns true", func(t *testing.T) {
		got, err := ms.ManualOverrides().Exists(context.Background(), 1, 2, 3, "r1")
		if err != nil {
			t.Fatal(err)
		}
		if !got {
			t.Error("U33a: ManualOverrides.Exists should return true for the exact (connector=3, rule=r1)")
		}
	})

	t.Run("different connector+rule returns false", func(t *testing.T) {
		got, err := ms.ManualOverrides().Exists(context.Background(), 1, 2, 4, "r2")
		if err != nil {
			t.Fatal(err)
		}
		if got {
			t.Error("U33b: ManualOverrides.Exists should return false for (connector=4, rule=r2)")
		}
	})
}
