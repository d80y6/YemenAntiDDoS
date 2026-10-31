// Package retention implements automatic cleanup of historical data.
package retention

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Config mirrors the retention section of the controller config.
type Config struct {
	TSStatsDays        int
	FlowLogsDays       int
	AttacksDays        int
	AuditLogDays       int
	IntervalHours      int
	TSStatsHypertable  bool
	FlowLogsHypertable bool
}

// Cleaner periodically deletes old data from the database.
type Cleaner struct {
	pool *pgxpool.Pool
	cfg  Config
}

func New(pool *pgxpool.Pool, cfg Config) *Cleaner {
	if cfg.IntervalHours <= 0 {
		cfg.IntervalHours = 24
	}
	return &Cleaner{pool: pool, cfg: cfg}
}

// Run starts the periodic cleanup loop. Blocks until ctx is cancelled.
func (c *Cleaner) Run(ctx context.Context) {
	// Run once on startup (after a short delay to let other services stabilize)
	select {
	case <-time.After(30 * time.Second):
		c.cleanup(ctx)
	case <-ctx.Done():
		return
	}

	ticker := time.NewTicker(time.Duration(c.cfg.IntervalHours) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.cleanup(ctx)
		}
	}
}

func (c *Cleaner) cleanup(ctx context.Context) {
	log.Println("retention: starting cleanup")
	total := int64(0)

	// ts_stats: skip row-delete when TimescaleDB manages retention via chunk policies
	if c.cfg.TSStatsDays > 0 && !c.cfg.TSStatsHypertable {
		n, err := c.deleteOld(ctx, "ts_stats", "time", c.cfg.TSStatsDays)
		if err != nil {
			log.Printf("retention: ts_stats cleanup error: %v", err)
		} else if n > 0 {
			log.Printf("retention: ts_stats deleted %d rows older than %d days", n, c.cfg.TSStatsDays)
			total += n
		}
	}

	if c.cfg.AttacksDays > 0 {
		// Only delete ended attacks (active attacks have ended_at IS NULL)
		n, err := c.deleteOldAttacks(ctx, c.cfg.AttacksDays)
		total += n
		if err != nil {
			log.Printf("retention: attacks cleanup error: %v", err)
		}
	}

	if c.cfg.AuditLogDays > 0 {
		n, err := c.deleteOld(ctx, "config_audit_log", "created_at", c.cfg.AuditLogDays)
		if err != nil {
			log.Printf("retention: audit_log cleanup error: %v", err)
		} else if n > 0 {
			log.Printf("retention: audit_log deleted %d rows older than %d days", n, c.cfg.AuditLogDays)
			total += n
		}
	}

	// flow_logs: skip row-delete when TimescaleDB manages retention via chunk policies
	if c.cfg.FlowLogsDays > 0 && !c.cfg.FlowLogsHypertable {
		n, err := c.deleteOld(ctx, "flow_logs", "time", c.cfg.FlowLogsDays)
		if err != nil {
			log.Printf("retention: flow_logs cleanup error: %v", err)
		} else if n > 0 {
			log.Printf("retention: flow_logs deleted %d rows older than %d days", n, c.cfg.FlowLogsDays)
			total += n
		}
	}

	if total == 0 {
		log.Println("retention: cleanup complete, nothing to delete")
	} else {
		log.Printf("retention: cleanup complete, %d total rows deleted", total)
	}
}

func (c *Cleaner) deleteOld(ctx context.Context, table, timeCol string, days int) (int64, error) {
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	q := fmt.Sprintf("DELETE FROM %s WHERE %s < $1", table, timeCol)
	tag, err := c.pool.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

var attackBatchLimit = 10000

func (c *Cleaner) deleteOldAttacks(ctx context.Context, days int) (int64, error) {
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	const old = `a.ended_at IS NOT NULL AND a.ended_at < $1`
	const terminal = `NOT EXISTS (SELECT 1 FROM xdrop_active_rules r WHERE r.attack_id = a.id AND r.status <> 'withdrawn')
	AND NOT EXISTS (SELECT 1 FROM bgp_announcement_attacks b WHERE b.attack_id = a.id AND b.detached_at IS NULL)
	AND NOT EXISTS (SELECT 1 FROM scheduled_actions s WHERE s.attack_id = a.id AND s.status IN ('pending','executing'))
	AND NOT EXISTS (SELECT 1 FROM bgp_announcement_attacks b JOIN bgp_announcements p ON p.id = b.announcement_id WHERE b.attack_id = a.id AND p.status NOT IN ('withdrawn','dismissed','dismissed_on_upgrade'))
	AND NOT EXISTS (SELECT 1 FROM action_execution_log l WHERE l.attack_id = a.id AND
	-- Guard 5 = xdrop_active_rules backfill WHERE: type; creation phases; success; connector; rule.
	l.action_type = 'xdrop' AND l.trigger_phase IN ('on_detected','confirmed','type_upgrade','updated') AND l.status = 'success' AND l.connector_id IS NOT NULL AND l.external_rule_id != ''
	-- Backfill withdrawal: xdrop; success; same attack/connector/rule; expiry phases (no action match).
	AND NOT EXISTS (SELECT 1 FROM action_execution_log l2 WHERE l2.action_type = 'xdrop' AND l2.status = 'success' AND l2.attack_id = l.attack_id AND l2.connector_id = l.connector_id
	AND l2.external_rule_id = l.external_rule_id AND l2.trigger_phase IN ('on_expired','expired','evicted'))
	-- Backfill override: manual_override success; same attack/connector/rule/action.
	AND NOT EXISTS (SELECT 1 FROM action_execution_log o WHERE o.trigger_phase = 'manual_override' AND o.status = 'success' AND o.attack_id = l.attack_id AND o.connector_id = l.connector_id AND o.external_rule_id = l.external_rule_id AND o.action_id = l.action_id)
	-- Additional terminal exclusion uses the complete state-table unique key, including action_id.
	AND NOT EXISTS (SELECT 1 FROM xdrop_active_rules r WHERE r.attack_id = l.attack_id AND r.action_id = l.action_id AND r.connector_id = l.connector_id AND r.external_rule_id = l.external_rule_id AND r.status = 'withdrawn'))
	AND NOT EXISTS (SELECT 1 FROM action_execution_log l WHERE l.attack_id = a.id AND
	-- Guard 6 = bgp_announcements backfill WHERE: type; creation phases; success; connector; rule; separator.
	l.action_type = 'bgp' AND l.trigger_phase IN ('on_detected','confirmed','type_upgrade','updated') AND l.status = 'success' AND l.connector_id IS NOT NULL AND l.external_rule_id != '' AND position('|' in l.external_rule_id) > 0
	-- Backfill override: manual_override success; same attack/connector/rule (no action match).
	AND NOT EXISTS (SELECT 1 FROM action_execution_log o WHERE o.trigger_phase = 'manual_override' AND o.status = 'success' AND o.attack_id = l.attack_id AND o.connector_id = l.connector_id AND o.external_rule_id = l.external_rule_id)
	-- Backfill withdrawal: bgp; expiry phases; success; same attack/rule/connector (no action match).
	AND NOT EXISTS (SELECT 1 FROM action_execution_log l2 WHERE l2.action_type = 'bgp'
	AND l2.trigger_phase IN ('on_expired','expired','evicted') AND l2.status = 'success' AND l2.attack_id = l.attack_id AND l2.external_rule_id = l.external_rule_id AND l2.connector_id = l.connector_id)
	-- Additional terminal exclusion matches the announcement's connector/prefix/route_map key.
	AND NOT EXISTS (SELECT 1 FROM bgp_announcements p WHERE p.connector_id = l.connector_id AND p.prefix = split_part(l.external_rule_id,'|',1) AND p.route_map = split_part(l.external_rule_id,'|',2) AND p.status IN ('withdrawn','dismissed','dismissed_on_upgrade')))`
	tables := []string{"action_execution_log", "xdrop_active_rules", "scheduled_actions", "bgp_announcement_attacks", "bgp_announcement_events", "action_manual_overrides", "actions_log", "attacks"}
	totals, kept := make([]int64, len(tables)), int64(0)
	defer func() {
		for i, table := range tables {
			log.Printf("retention: %s deleted %d rows", table, totals[i])
		}
	}()
	for first := true; ; first = false {
		n, err := func() (int, error) {
			tx, err := c.pool.Begin(ctx)
			if err != nil {
				return 0, fmt.Errorf("begin tx: %w", err)
			}
			defer tx.Rollback(ctx)
			if first {
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM attacks a WHERE "+old+" AND NOT ("+terminal+")", cutoff).Scan(&kept); err != nil {
					return 0, fmt.Errorf("count kept attacks: %w", err)
				}
			}
			rows, err := tx.Query(ctx, "SELECT id FROM attacks a WHERE "+old+" AND "+terminal+" ORDER BY id LIMIT $2 FOR UPDATE", cutoff, attackBatchLimit)
			if err != nil {
				return 0, fmt.Errorf("select attacks: %w", err)
			}
			victims, err := pgx.CollectRows(rows, pgx.RowTo[int])
			if err != nil {
				return 0, fmt.Errorf("read attacks: %w", err)
			}
			counts := make([]int64, len(tables))
			for i, table := range tables {
				if len(victims) == 0 {
					break
				}
				predicate := "attack_id = ANY($2)"
				if table == "attacks" {
					predicate = "id IN (SELECT unnest($2::int[]))"
				}
				// Bind the shared cutoff as $1, keeping the identical victims slice in $2.
				tag, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE "+predicate+" AND $1::timestamptz IS NOT NULL", cutoff, victims)
				if err != nil {
					return 0, fmt.Errorf("delete %s: %w", table, err)
				}
				counts[i] = tag.RowsAffected()
			}
			// Once per round, in its first transaction, including an empty victims list.
			if first {
				tag, err := tx.Exec(ctx, `DELETE FROM bgp_announcement_events e WHERE e.created_at < $1 AND EXISTS (SELECT 1 FROM bgp_announcements p WHERE p.id = e.announcement_id AND p.status IN ('withdrawn','dismissed','dismissed_on_upgrade'))`, cutoff)
				if err != nil {
					return 0, fmt.Errorf("delete terminal announcement events: %w", err)
				}
				counts[4] += tag.RowsAffected()
			}
			if err := tx.Commit(ctx); err != nil {
				return 0, fmt.Errorf("commit: %w", err)
			}
			for i := range totals {
				totals[i] += counts[i]
			}
			return len(victims), nil
		}()
		if err != nil {
			return totals[7], err
		}
		if n < attackBatchLimit {
			break
		}
	}
	log.Printf("retention: kept %d ended attacks with unfinished state", kept)
	return totals[7], nil
}
