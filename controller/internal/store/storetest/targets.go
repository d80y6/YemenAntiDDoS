package storetest

import "github.com/littlewolf9527/xsight/controller/internal/store"

// TargetsDone is the in-memory repository model shared by the test stores.
// Callers hold the mutex that owns logs.
func TargetsDone(logs []store.ActionExecutionLog, attackID, actionID int, phase string) bool {
	latest := map[int]store.ActionExecutionLog{}
	later := func(a, b store.ActionExecutionLog) bool {
		return a.ExecutedAt.After(b.ExecutedAt) || a.ExecutedAt.Equal(b.ExecutedAt) && a.ID > b.ID
	}
	for _, l := range logs {
		if l.AttackID != attackID || l.ActionID != actionID || l.TriggerPhase != phase || l.Status == "skipped" {
			continue
		}
		target := 0
		if l.ConnectorID != nil {
			target = *l.ConnectorID
		}
		if old, ok := latest[target]; !ok || later(l, old) {
			latest[target] = l
		}
	}
	if len(latest) == 0 {
		return false
	}
	if empty, ok := latest[0]; ok {
		for target, l := range latest {
			if target != 0 && later(l, empty) {
				delete(latest, 0)
				break
			}
		}
	}
	for _, l := range latest {
		if l.Status != "success" && l.Status != "scheduled" {
			return false
		}
	}
	return true
}
