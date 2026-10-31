package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type actionExecLogRepo struct{ pool *pgxpool.Pool }

func (r *actionExecLogRepo) Create(ctx context.Context, l *store.ActionExecutionLog) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO action_execution_log
		 (attack_id, action_id, response_name, action_type, connector_name, trigger_phase,
		  status, status_code, error_message, request_body, response_body, external_rule_id,
		  connector_id, duration_ms, scheduled_for, detail, skip_reason)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) RETURNING id`,
		l.AttackID, l.ActionID, l.ResponseName, l.ActionType, l.ConnectorName, l.TriggerPhase,
		l.Status, l.StatusCode, l.ErrorMessage, l.RequestBody, l.ResponseBody, l.ExternalRuleID,
		l.ConnectorID, l.DurationMs, l.ScheduledFor, l.Detail, l.SkipReason).
		Scan(&id)
	return id, err
}

func (r *actionExecLogRepo) ListByAttack(ctx context.Context, attackID int) ([]store.ActionExecutionLog, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, attack_id, action_id, response_name, action_type, connector_name, trigger_phase,
		        status, status_code, error_message, request_body, response_body, external_rule_id,
		        connector_id, duration_ms, executed_at, scheduled_for,
		        COALESCE(detail, ''), COALESCE(skip_reason, '')
		 FROM action_execution_log
		 WHERE attack_id=$1 ORDER BY executed_at DESC`, attackID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.ActionExecutionLog
	for rows.Next() {
		var l store.ActionExecutionLog
		if err := rows.Scan(&l.ID, &l.AttackID, &l.ActionID, &l.ResponseName, &l.ActionType,
			&l.ConnectorName, &l.TriggerPhase, &l.Status, &l.StatusCode, &l.ErrorMessage,
			&l.RequestBody, &l.ResponseBody, &l.ExternalRuleID, &l.ConnectorID, &l.DurationMs, &l.ExecutedAt, &l.ScheduledFor,
			&l.Detail, &l.SkipReason); err != nil {
			return nil, err
		}
		list = append(list, l)
	}
	return list, rows.Err()
}

func (r *actionExecLogRepo) AllTargetsDone(ctx context.Context, attackID, actionID int, triggerPhase string) (bool, error) {
	var done bool
	err := r.pool.QueryRow(ctx, `WITH latest AS (
	 SELECT DISTINCT ON (COALESCE(connector_id, 0))
	        COALESCE(connector_id, 0) AS target, status, executed_at, id
	 FROM action_execution_log
	 WHERE attack_id=$1 AND action_id=$2 AND trigger_phase=$3 AND status <> 'skipped'
	 ORDER BY COALESCE(connector_id, 0), executed_at DESC, id DESC
	)
	SELECT COALESCE(bool_and(status IN ('success','scheduled')), false)
	FROM latest l WHERE target <> 0 OR NOT EXISTS (
	 SELECT 1 FROM latest newer WHERE newer.target <> 0
	 AND (newer.executed_at, newer.id) > (l.executed_at, l.id)
	)`, attackID, actionID, triggerPhase).Scan(&done)
	return done, err
}
