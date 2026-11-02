package tests

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/storetest"
)

type mockContractBackend struct{ ms *MockStore }

func (b *mockContractBackend) Store() store.Store { return b.ms }

// SetTime changes only fixture timestamps, under the owning repository lock.
// Keeping this adapter in the new runner leaves the baseline mock byte-identical for K3.
func (b *mockContractBackend) SetTime(table, idColumn string, id int, column string, value time.Time) error {
	var mu *sync.Mutex
	var records any
	field, key := "", "ID"
	switch table {
	case "action_execution_log":
		if column == "executed_at" {
			field = "ExecutedAt"
		}
		mu = &b.ms.actionExecLog.mu
		records = &b.ms.actionExecLog.logs
	case "action_manual_overrides":
		if column == "created_at" {
			field = "CreatedAt"
		}
		mu = &b.ms.manualOverrides.mu
		records = &b.ms.manualOverrides.records
	case "xdrop_active_rules":
		if column == "created_at" {
			field = "CreatedAt"
		}
		mu = &b.ms.xdropActiveRules.mu
		records = &b.ms.xdropActiveRules.records
	case "bgp_announcements":
		if column == "announced_at" {
			field = "AnnouncedAt"
		}
		mu = &b.ms.bgpAnnouncements.mu
		records = &b.ms.bgpAnnouncements.announcements
	case "bgp_announcement_attacks":
		if column == "attached_at" {
			field = "AttachedAt"
		}
		mu = &b.ms.bgpAnnouncements.mu
		records = &b.ms.bgpAnnouncements.attacks
		if idColumn == "attack_id" {
			key = "AttackID"
		} else if idColumn == "announcement_id" {
			key = "AnnouncementID"
		} else {
			return fmt.Errorf("unsupported attachment key %q", idColumn)
		}
	case "bgp_announcement_events":
		if column == "created_at" {
			field = "CreatedAt"
		}
		mu = &b.ms.bgpAnnouncements.mu
		records = &b.ms.bgpAnnouncements.events
	default:
		return fmt.Errorf("unsupported fixture table %q", table)
	}
	if field == "" || (table != "bgp_announcement_attacks" && idColumn != "id") {
		return fmt.Errorf("unsupported fixture column/key %s.%s/%s", table, column, idColumn)
	}
	mu.Lock()
	defer mu.Unlock()
	rows := reflect.ValueOf(records).Elem()
	matched := 0
	for i := 0; i < rows.Len(); i++ {
		r := rows.Index(i)
		if r.FieldByName(key).Int() == int64(id) {
			r.FieldByName(field).Set(reflect.ValueOf(value))
			matched++
		}
	}
	if matched != 1 {
		return fmt.Errorf("fixture %s %s=%d matched %d rows; want 1", table, idColumn, id, matched)
	}
	return nil
}

func TestStoreContract_Mock(t *testing.T) {
	storetest.RunContract(t, func(t *testing.T) storetest.Backend { return &mockContractBackend{ms: NewMockStore()} })
}

// These self-tests cover the supporting mock fixtures, not extra shared SQL contracts.
func TestStoreContract_CascadeHelperMocks(t *testing.T) {
	ctx := context.Background()
	for _, binding := range []string{"TemplateID", "PrefixID"} {
		for _, source := range []string{"CreateInput", "GetOutput"} {
			t.Run("Threshold/"+binding+"/"+source, func(t *testing.T) {
				ms := NewMockStore()
				bindingID, responseID := 11, 22
				input := store.Threshold{ResponseID: &responseID, Domain: "subnet", Direction: "receives", Decoder: "udp", Unit: "pps", Comparison: "over", Value: 100, Enabled: true}
				if binding == "TemplateID" {
					input.TemplateID = &bindingID
				} else {
					input.PrefixID = &bindingID
				}
				id, err := ms.Thresholds().Create(ctx, &input)
				if err != nil {
					t.Fatal(err)
				}
				changed := &input
				if source == "GetOutput" {
					changed, err = ms.Thresholds().Get(ctx, id)
					if err != nil {
						t.Fatal(err)
					}
				}
				p := changed.TemplateID
				if binding == "PrefixID" {
					p = changed.PrefixID
				}
				if p == nil || changed.ResponseID == nil {
					t.Fatal("seed lost a non-NULL association")
				}
				*p, *changed.ResponseID = 77, 88
				got, err := ms.Thresholds().Get(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				p, absent := got.TemplateID, got.PrefixID
				if binding == "PrefixID" {
					p, absent = got.PrefixID, got.TemplateID
				}
				// postgres/threshold.go: thresholdRepo.Create writes values; Get scans independent pointers.
				if p == nil || *p != 11 || got.ResponseID == nil || *got.ResponseID != 22 || absent != nil {
					t.Errorf("%s changed stored associations: %s=%v, response=%v, unused=%v; want 11, 22, nil", source, binding, p, got.ResponseID, absent)
				}
			})
		}
	}
	t.Run("Threshold/NilResponseID", func(t *testing.T) {
		ms := NewMockStore()
		bindingID := 11
		id, err := ms.Thresholds().Create(ctx, &store.Threshold{TemplateID: &bindingID})
		if err != nil {
			t.Fatal(err)
		}
		got, err := ms.Thresholds().Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		// postgres/threshold.go: thresholdRepo.Create/Get preserve nullable pointer columns.
		if got.TemplateID == nil || *got.TemplateID != 11 || got.PrefixID != nil || got.ResponseID != nil {
			t.Errorf("nullable threshold associations changed: %+v", got)
		}
	})
	for _, populated := range []bool{false, true} {
		name := "Defaults"
		if populated {
			name = "IgnoresCallerCountsAndTimes"
		}
		t.Run("Template/Projection/"+name, func(t *testing.T) {
			ms := NewMockStore()
			old := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
			input := store.ThresholdTemplate{Name: "fixture", Description: "description"}
			if populated {
				input.ID, input.RuleCount, input.PrefixCount = 99, 7, 9
				input.CreatedAt, input.UpdatedAt = old, old
			}
			id, err := ms.ThresholdTemplates().Create(ctx, &input)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ms.ThresholdTemplates().Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			// postgres/template.go: templateRepo.Create writes only name/description/response_id;
			// postgres.go:migrations supplies both DEFAULT now() values; Get omits counts.
			if got.ID != id || id == 99 || got.Name != "fixture" || got.Description != "description" || got.ResponseID != nil {
				t.Errorf("unexpected template identity/writable columns: %+v", got)
			}
			if got.RuleCount != 0 || got.PrefixCount != 0 {
				t.Errorf("Get retained caller counts: %d/%d; want 0/0", got.RuleCount, got.PrefixCount)
			}
			if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() || got.CreatedAt.Equal(old) || got.UpdatedAt.Equal(old) || !got.CreatedAt.Equal(got.UpdatedAt) {
				t.Errorf("Create must generate both default timestamps, ignoring caller times: %v / %v", got.CreatedAt, got.UpdatedAt)
			}
		})
	}
	for _, source := range []string{"CreateInput", "GetOutput"} {
		t.Run("Template/ResponseID/"+source, func(t *testing.T) {
			ms := NewMockStore()
			responseID := 22
			input := store.ThresholdTemplate{Name: "fixture", ResponseID: &responseID}
			id, err := ms.ThresholdTemplates().Create(ctx, &input)
			if err != nil {
				t.Fatal(err)
			}
			changed := &input
			if source == "GetOutput" {
				changed, err = ms.ThresholdTemplates().Get(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
			}
			if changed.ResponseID == nil {
				t.Fatal("seed lost response association")
			}
			*changed.ResponseID = 88
			changed.Name = "changed"
			got, err := ms.ThresholdTemplates().Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			// postgres/template.go: templateRepo.Create/Get write and scan independent values.
			if got.ResponseID == nil || *got.ResponseID != 22 || got.Name != "fixture" {
				t.Errorf("%s changed stored template: %+v; want response 22 and name fixture", source, got)
			}
		})
	}
}
