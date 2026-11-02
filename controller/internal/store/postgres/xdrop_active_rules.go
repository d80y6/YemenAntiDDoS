package postgres

// v1.2 PR-4: xdrop_active_rules repo — authoritative state for xDrop rules.

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type xdropActiveRuleRepo struct{ pool *pgxpool.Pool }

func (r *xdropActiveRuleRepo) ClaimActive(ctx context.Context, attackID, actionID, connectorID int, externalRuleID string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `UPDATE xdrop_active_rules SET status='withdrawing'
		WHERE attack_id=$1 AND action_id=$2 AND connector_id=$3 AND external_rule_id=$4 AND status='active'`, attackID, actionID, connectorID, externalRuleID)
	return tag.RowsAffected() > 0, err
}

func (r *xdropActiveRuleRepo) Upsert(ctx context.Context, rule *store.XDropActiveRule) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO xdrop_active_rules
		 (attack_id, action_id, connector_id, external_rule_id, status, delay_minutes, delay_started_at, error_message)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (attack_id, action_id, connector_id, external_rule_id)
		 DO UPDATE SET status = EXCLUDED.status,
		               delay_minutes = EXCLUDED.delay_minutes,
		               delay_started_at = EXCLUDED.delay_started_at,
		               error_message = EXCLUDED.error_message
		 WHERE xdrop_active_rules.status <> 'withdrawn'
		 RETURNING id`,
		rule.AttackID, rule.ActionID, rule.ConnectorID, rule.ExternalRuleID,
		rule.Status, rule.DelayMinutes, rule.DelayStartedAt, rule.ErrorMessage,
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		err = r.pool.QueryRow(ctx, `SELECT id FROM xdrop_active_rules WHERE attack_id=$1 AND action_id=$2 AND connector_id=$3 AND external_rule_id=$4`,
			rule.AttackID, rule.ActionID, rule.ConnectorID, rule.ExternalRuleID).Scan(&id)
	}
	if err != nil {
		return 0, fmt.Errorf("upsert xdrop_active_rule: %w", err)
	}
	return id, nil
}

// MarkWithdrawing claims active/delayed/failed rows; an unclaimed row returns false, nil.
// MarkDelayed and MarkFailed also return nil when their status guards match no rows.
func (r *xdropActiveRuleRepo) MarkWithdrawing(ctx context.Context, attackID, actionID, connectorID int, externalRuleID string) (bool, error) {
	tag, err := r.pool.Exec(ctx,
		`UPDATE xdrop_active_rules
		 SET status = 'withdrawing'
		 WHERE attack_id=$1 AND action_id=$2 AND connector_id=$3 AND external_rule_id=$4
		   AND status IN ('active','delayed','failed')`,
		attackID, actionID, connectorID, externalRuleID)
	if err != nil {
		return false, fmt.Errorf("mark withdrawing: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (r *xdropActiveRuleRepo) MarkWithdrawn(ctx context.Context, attackID, actionID, connectorID int, externalRuleID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE xdrop_active_rules
		 SET status='withdrawn', withdrawn_at=now(), error_message=''
		 WHERE attack_id=$1 AND action_id=$2 AND connector_id=$3 AND external_rule_id=$4`,
		attackID, actionID, connectorID, externalRuleID)
	if err != nil {
		return fmt.Errorf("mark withdrawn: %w", err)
	}
	return nil
}

func (r *xdropActiveRuleRepo) MarkFailed(ctx context.Context, attackID, actionID, connectorID int, externalRuleID, errMsg string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE xdrop_active_rules
		 SET status='failed', error_message=$5
		 WHERE attack_id=$1 AND action_id=$2 AND connector_id=$3 AND external_rule_id=$4 AND status <> 'withdrawn'`,
		attackID, actionID, connectorID, externalRuleID, errMsg)
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	return nil
}

func (r *xdropActiveRuleRepo) MarkDelayed(ctx context.Context, attackID, actionID, connectorID int, externalRuleID string, delayMinutes int) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE xdrop_active_rules
		 SET status='delayed', delay_started_at=now(), delay_minutes=$5
		 WHERE attack_id=$1 AND action_id=$2 AND connector_id=$3 AND external_rule_id=$4 AND status IN ('active','failed')`,
		attackID, actionID, connectorID, externalRuleID, delayMinutes)
	if err != nil {
		return fmt.Errorf("mark delayed: %w", err)
	}
	return nil
}

func (r *xdropActiveRuleRepo) ListActive(ctx context.Context) ([]store.XDropActiveRule, error) {
	return r.listByStatus(ctx, `status IN ('active','delayed','failed')`)
}

func (r *xdropActiveRuleRepo) ListWithdrawing(ctx context.Context) ([]store.XDropActiveRule, error) {
	return r.listByStatus(ctx, `status = 'withdrawing'`)
}

func (r *xdropActiveRuleRepo) ListByAttack(ctx context.Context, attackID int) ([]store.XDropActiveRule, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, attack_id, action_id, connector_id, external_rule_id,
		        status, delay_started_at, delay_minutes, COALESCE(error_message, ''),
		        created_at, withdrawn_at
		 FROM xdrop_active_rules WHERE attack_id=$1
		 ORDER BY created_at DESC`, attackID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanXDropActiveRules(rows)
}

// CountByStatus returns status → row count for all xdrop_active_rules.
// Used by the Prometheus xsight_xdrop_rules gauge collector.
func (r *xdropActiveRuleRepo) CountByStatus(ctx context.Context) (map[string]int, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT status, COUNT(*) FROM xdrop_active_rules GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[status] = n
	}
	return out, rows.Err()
}

func (r *xdropActiveRuleRepo) listByStatus(ctx context.Context, where string) ([]store.XDropActiveRule, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, attack_id, action_id, connector_id, external_rule_id,
		        status, delay_started_at, delay_minutes, COALESCE(error_message, ''),
		        created_at, withdrawn_at
		 FROM xdrop_active_rules
		 WHERE `+where+`
		 ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanXDropActiveRules(rows)
}

func scanXDropActiveRules(rows rowScanner) ([]store.XDropActiveRule, error) {
	var out []store.XDropActiveRule
	for rows.Next() {
		var r store.XDropActiveRule
		if err := rows.Scan(&r.ID, &r.AttackID, &r.ActionID, &r.ConnectorID,
			&r.ExternalRuleID, &r.Status, &r.DelayStartedAt, &r.DelayMinutes,
			&r.ErrorMessage, &r.CreatedAt, &r.WithdrawnAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (r *xdropActiveRuleRepo) CountLiveByConnector(ctx context.Context, connectorID int) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM xdrop_active_rules
 WHERE connector_id=$1 AND status IN ('active','delayed','withdrawing','failed')`, connectorID).Scan(&n)
	return n, err
}
