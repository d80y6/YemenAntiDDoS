package action

import (
	"context"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type td104EmptyBGP struct{ store.BGPAnnouncementRepo }

func (td104EmptyBGP) ListAttachmentsForAttack(context.Context, int) ([]store.BGPAnnouncementAttack, error) {
	return nil, nil
}
func (s *v3Store) BGPAnnouncements() store.BGPAnnouncementRepo { return td104EmptyBGP{} }
func (r v3Active) ClaimActive(_ context.Context, a, b, c int, id string) (bool, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	key := v3RuleKey(a, b, c, id)
	row, ok := r.s.rules[key]
	if !ok || row.Status != "active" {
		return false, nil
	}
	row.Status = "withdrawing"
	r.s.rules[key] = row
	r.s.history[key] = append(r.s.history[key], row.Status)
	return true, nil
}
