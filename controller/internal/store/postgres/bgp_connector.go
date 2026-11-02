package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type bgpConnectorRepo struct{ pool *pgxpool.Pool }

const bgpConnectorCols = `id, name, vtysh_path, bgp_asn, address_family, enabled, description,
	COALESCE(vendor, 'frr'), COALESCE(flowspec_enabled, false), created_at, updated_at`

func (r *bgpConnectorRepo) List(ctx context.Context) ([]store.BGPConnector, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+bgpConnectorCols+` FROM bgp_connectors ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.BGPConnector
	for rows.Next() {
		var c store.BGPConnector
		if err := rows.Scan(&c.ID, &c.Name, &c.VtyshPath, &c.BGPASN,
			&c.AddressFamily, &c.Enabled, &c.Description, &c.Vendor, &c.FlowspecEnabled,
			&c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

func (r *bgpConnectorRepo) Get(ctx context.Context, id int) (*store.BGPConnector, error) {
	var c store.BGPConnector
	err := r.pool.QueryRow(ctx,
		`SELECT `+bgpConnectorCols+` FROM bgp_connectors WHERE id=$1`, id).
		Scan(&c.ID, &c.Name, &c.VtyshPath, &c.BGPASN,
			&c.AddressFamily, &c.Enabled, &c.Description, &c.Vendor, &c.FlowspecEnabled,
			&c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("bgp_connector %d: %w", id, err)
	}
	return &c, nil
}

func (r *bgpConnectorRepo) Create(ctx context.Context, c *store.BGPConnector) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO bgp_connectors (name, vtysh_path, bgp_asn, address_family, enabled, description, vendor, flowspec_enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		c.Name, c.VtyshPath, c.BGPASN, c.AddressFamily, c.Enabled, c.Description, c.Vendor, c.FlowspecEnabled).Scan(&id)
	return id, err
}

func (r *bgpConnectorRepo) Update(ctx context.Context, c *store.BGPConnector) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE bgp_connectors
		 SET name=$1, vtysh_path=$2, bgp_asn=$3, address_family=$4, enabled=$5, description=$6,
		     vendor=$7, flowspec_enabled=$8, updated_at=now()
		 WHERE id=$9`,
		c.Name, c.VtyshPath, c.BGPASN, c.AddressFamily, c.Enabled, c.Description,
		c.Vendor, c.FlowspecEnabled, c.ID)
	return err
}

func (r *bgpConnectorRepo) Delete(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM bgp_connectors WHERE id=$1`, id)
	return err
}
