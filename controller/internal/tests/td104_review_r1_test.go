package tests

import (
	"testing"
	"testing/synctest"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// Historical execution logs do not own a still-active state-table row.
func TestTD104_E23b_LegacyAlreadyExecutedOwnsRule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.onlyXDrop()
		// Persisted legacy success owns this still-active rule (for example,
		// DELETE succeeded historically while terminal-state persistence failed).
		f.s.responses.actions[1].TriggerPhase = ""
		f.s.responses.actions[1].ExecutionPolicy = "once_on_exit"
		_, err := f.s.ActionsLog().Create(fzCtx, &store.ActionLog{AttackID: 20, ActionID: 31, Status: "success"})
		fzCheck(t, err)
		f.run()
		fzEqual(t, "legacy sweep DELETE", f.d.count(), 1)
		fzEqual(t, "legacy skipped event still scans", f.s.count("rules") > 0, true)
		rows, err := f.s.MockStore.XDropActiveRules().ListByAttack(fzCtx, 20)
		fzCheck(t, err)
		fzEqual(t, "rule terminal", rows[0].Status, "withdrawn")
		f.delta(t, map[string]float64{"xdrop/dispatched": 1})
	})
}
