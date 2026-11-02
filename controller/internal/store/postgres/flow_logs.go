package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type flowLogRepo struct{ pool *pgxpool.Pool }

// BulkInsert writes flow log entries using pgx.CopyFrom for maximum throughput.
func (r *flowLogRepo) BulkInsert(ctx context.Context, flows []store.FlowLog) error {
	if len(flows) == 0 {
		return nil
	}

	columns := []string{
		"time", "node_id", "prefix", "src_ip", "dst_ip",
		"src_port", "dst_port", "protocol", "tcp_flags",
		"packets", "bytes",
	}

	rows := make([][]any, len(flows))
	for i, f := range flows {
		rows[i] = []any{
			f.Time, f.NodeID, f.Prefix, f.SrcIP, f.DstIP,
			f.SrcPort, f.DstPort, f.Protocol, f.TCPFlags,
			f.Packets, f.Bytes,
		}
	}

	_, err := r.pool.CopyFrom(ctx,
		pgx.Identifier{"flow_logs"},
		columns,
		pgx.CopyFromRows(rows),
	)
	return err
}

// QueryByDstIP returns flow logs matching a destination IP within a time window,
// sorted by packets descending.
func (r *flowLogRepo) QueryByDstIP(ctx context.Context, filter store.FlowLogFilter) ([]store.FlowLog, error) {
	q, args := flowLogQuery(filter, "dst_ip")

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []store.FlowLog
	for rows.Next() {
		var f store.FlowLog
		if err := rows.Scan(
			&f.Time, &f.NodeID, &f.Prefix, &f.SrcIP, &f.DstIP,
			&f.SrcPort, &f.DstPort, &f.Protocol, &f.TCPFlags,
			&f.Packets, &f.Bytes,
		); err != nil {
			return nil, err
		}
		result = append(result, f)
	}
	return result, rows.Err()
}

// QueryBySrcIP queries flow_logs by source IP for outbound attack sensor logs.
func (r *flowLogRepo) QueryBySrcIP(ctx context.Context, filter store.FlowLogFilter) ([]store.FlowLog, error) {
	q, args := flowLogQuery(filter, "src_ip")

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []store.FlowLog
	for rows.Next() {
		var f store.FlowLog
		if err := rows.Scan(
			&f.Time, &f.NodeID, &f.Prefix, &f.SrcIP, &f.DstIP,
			&f.SrcPort, &f.DstPort, &f.Protocol, &f.TCPFlags,
			&f.Packets, &f.Bytes,
		); err != nil {
			return nil, err
		}
		result = append(result, f)
	}
	return result, rows.Err()
}

func flowLogWhere(filter store.FlowLogFilter, addrCol string) (string, []any) {
	var conds []string
	var args []any
	argN := 1

	if filter.DstIP != "" {
		if strings.Contains(filter.DstIP, "/") {
			conds = append(conds, fmt.Sprintf("%s <<= $%d::CIDR", addrCol, argN))
		} else {
			conds = append(conds, fmt.Sprintf("%s = $%d::INET", addrCol, argN))
		}
		args = append(args, filter.DstIP)
		argN++
	}

	if !filter.From.IsZero() {
		conds = append(conds, fmt.Sprintf("time >= $%d", argN))
		args = append(args, filter.From)
		argN++
	}

	if !filter.To.IsZero() {
		conds = append(conds, fmt.Sprintf("time <= $%d", argN))
		args = append(args, filter.To)
		argN++
	}

	if len(filter.Protocols) > 0 {
		conds = append(conds, fmt.Sprintf("protocol = ANY($%d)", argN))
		args = append(args, filter.Protocols)
		argN++
	}
	if filter.TCPFlagsAll != 0 {
		conds = append(conds, fmt.Sprintf("tcp_flags & $%d = $%d", argN, argN))
		args = append(args, int(filter.TCPFlagsAll))
		argN++
	}
	if filter.TCPFlagsNone != 0 {
		conds = append(conds, fmt.Sprintf("tcp_flags & $%d = 0", argN))
		args = append(args, int(filter.TCPFlagsNone))
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	return where, args
}

func flowLogQuery(filter store.FlowLogFilter, addrCol string) (string, []any) {
	where, args := flowLogWhere(filter, addrCol)
	limit := 1000
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	if limit > 10000 {
		limit = 10000
	}

	return fmt.Sprintf(`SELECT time, node_id, prefix::TEXT, src_ip::TEXT, dst_ip::TEXT,
		src_port, dst_port, protocol, tcp_flags, packets, bytes
		FROM flow_logs%s
		ORDER BY packets DESC
		LIMIT %d`, where, limit), args
}
