package tests

import "context"

func (r *mockXDropActiveRuleRepo) ClaimActive(_ context.Context, a, b, c int, key string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.findIdxLocked(a, b, c, key)
	if i < 0 || r.records[i].Status != "active" {
		return false, nil
	}
	r.records[i].Status = "withdrawing"
	return true, nil
}
