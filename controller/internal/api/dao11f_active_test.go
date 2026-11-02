package api

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type dao11fActiveStore struct{ store.Store }

func (dao11fActiveStore) BGPAnnouncements() store.BGPAnnouncementRepo { return dao11fActiveBGP{} }
func (dao11fActiveStore) BGPConnectors() store.BGPConnectorRepo       { return dao11fActiveConnectors{} }
func (dao11fActiveStore) XDropActiveRules() store.XDropActiveRuleRepo { return dao11fActiveXDrop{} }
func (dao11fActiveStore) Attacks() store.AttackRepo                   { return dao11fActiveAttacks{} }
func (dao11fActiveStore) ActionExecLog() store.ActionExecLogRepo      { return dao11fActiveLogs{} }

type dao11fActiveBGP struct{ store.BGPAnnouncementRepo }

func (dao11fActiveBGP) ListActive(context.Context) ([]store.BGPAnnouncement, error) {
	return []store.BGPAnnouncement{
		{ID: 701, Status: "future-bgp-status", ConnectorID: 7},
		{ID: 702, Status: "active", ConnectorID: 7, Prefix: "192.0.2.0/24", RouteMap: "RTBH"},
	}, nil
}
func (dao11fActiveBGP) ListAttacks(context.Context, int) ([]store.BGPAnnouncementAttack, error) {
	return nil, nil
}

type dao11fActiveConnectors struct{ store.BGPConnectorRepo }

func (dao11fActiveConnectors) Get(context.Context, int) (*store.BGPConnector, error) {
	return &store.BGPConnector{ID: 7, Name: "fixture-bgp", Enabled: true}, nil
}

type dao11fActiveXDrop struct{ store.XDropActiveRuleRepo }

func (dao11fActiveXDrop) ListActive(context.Context) ([]store.XDropActiveRule, error) {
	return []store.XDropActiveRule{
		{ID: 801, AttackID: 20, Status: "future-xdrop-status", ExternalRuleID: "unknown-rule"},
		{ID: 802, AttackID: 21, Status: "active", ExternalRuleID: "known-rule"},
	}, nil
}

type dao11fActiveAttacks struct{ store.AttackRepo }

func (dao11fActiveAttacks) Get(_ context.Context, id int) (*store.Attack, error) {
	return &store.Attack{ID: id, DstIP: "192.0.2.10"}, nil
}

type dao11fActiveLogs struct{ store.ActionExecLogRepo }

func (dao11fActiveLogs) ListByAttack(context.Context, int) ([]store.ActionExecutionLog, error) {
	return nil, nil
}

func dao11fActive(t *testing.T, bgp bool) {
	t.Helper()
	var capture bytes.Buffer
	old := log.Writer()
	log.SetOutput(&capture)
	defer log.SetOutput(old)
	ctx := &gin.Context{}
	s := dao11fActiveStore{}
	build := buildActiveXDropFromTable
	wantWarning := `WARN api: buildActiveXDropFromTable unknown status "future-xdrop-status" id=801; row hidden from Mitigations`
	if bgp {
		build = buildActiveBGPFromAnnouncements
		wantWarning = `WARN api: buildActiveBGPFromAnnouncements unknown status "future-bgp-status" id=701; row hidden from Mitigations`
	}
	rows, err := build(ctx, s)
	if err != nil || len(rows) != 1 {
		t.Fatalf("visible rows=%+v error=%v; want one known row", rows, err)
	}
	known := rows[0].Status == "active"
	if bgp {
		known = known && rows[0].AnnouncementID == 702 && rows[0].ActionType == "bgp"
	} else {
		known = known && rows[0].AttackID == 21 && rows[0].ExternalRuleID == "known-rule" && rows[0].ActionType == "xdrop"
	}
	if !known {
		t.Errorf("visible rows=%+v; want only the known active row", rows)
	} else {
		t.Log("visible list contains only the known active row: PASS")
	}
	if n := strings.Count(capture.String(), "WARN api:"); n != 1 {
		t.Errorf("all api WARN lines=%d; want 1 (known rows must not warn); log=%q", n, capture.String())
	}
	if strings.Count(capture.String(), wantWarning) != 1 {
		t.Errorf("missing WARN with status and row id: want %q; log=%q", wantWarning, capture.String())
	} else {
		t.Logf("WARN with status and row id: PASS: %s", wantWarning)
	}
}

func TestDao11f_G2_BGPUnknownStatus(t *testing.T)   { dao11fActive(t, true) }
func TestDao11f_G2_XDropUnknownStatus(t *testing.T) { dao11fActive(t, false) }
