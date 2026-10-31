package tests

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type dao11hOverrideStore struct{ *MockStore }

func (s dao11hOverrideStore) ManualOverrides() store.ActionManualOverrideRepo {
	return dao11hOverrides{s.MockStore.ManualOverrides()}
}

type dao11hOverrides struct{ store.ActionManualOverrideRepo }

func (dao11hOverrides) Exists(context.Context, int, int, int, string) (bool, error) {
	return false, errors.New("dao11h override lookup unavailable")
}

func TestDao11h_BGPWithdrawOverrideLookupError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture, _, event, conn, announcementID := dao5BGPFixture(t, 0)
		s := dao11hOverrideStore{fixture.MockStore}
		script, record := dao4Vtysh(t)
		conn.VtyshPath = script
		s.bgpConnectors.connectors = []store.BGPConnector{*conn}
		captured := dao5CaptureLog(t)
		engine := action.NewEngine(s, "auto")
		engine.HandleEvent(event)
		synctest.Wait()

		if output := captured.text(); !strings.Contains(output, "bgp withdraw override lookup: dao11h override lookup unavailable") {
			t.Errorf("T1.Log: missing override lookup error: %s", output)
		} else {
			t.Log("T1.Log: PASS override lookup error is logged")
		}
		commands := dao4Read(t, record)
		if calls := strings.Count(commands, "no network 192.0.2.10/32 route-map RTBH"); calls != 1 {
			t.Errorf("T1.WithdrawCall: got %d calls; want 1; commands=%q", calls, commands)
		} else {
			t.Log("T1.WithdrawCall: PASS vtysh withdraw called once")
		}
		row, err := s.BGPAnnouncements().Get(context.Background(), announcementID)
		if err != nil || row == nil || row.Status != "withdrawn" {
			t.Errorf("T1.Withdrawn: row=%+v err=%v; want withdrawn", row, err)
		} else {
			t.Log("T1.Withdrawn: PASS announcement is withdrawn")
		}
		// The ended sweep can repair the withdrawal without writing an execution log.
		// Require this event's success row so a premature return cannot pass silently.
		logs := s.actionExecLog.snapshotLogs()
		matches := 0
		for _, entry := range logs {
			if entry.AttackID == event.DBID && entry.ActionID == s.responses.actions[0].ID &&
				entry.ActionType == "bgp" && entry.TriggerPhase == "on_expired" && entry.Status == "success" {
				matches++
			}
		}
		if matches == 0 {
			t.Errorf("T1.SuccessExecLog: no success log for attack=%d action=%d phase=on_expired; logs=%+v", event.DBID, s.responses.actions[0].ID, logs)
		} else {
			t.Logf("T1.SuccessExecLog: PASS found %d matching success log(s)", matches)
		}
	})
}
