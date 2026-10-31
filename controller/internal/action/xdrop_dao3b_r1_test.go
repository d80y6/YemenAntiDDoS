package action

import "testing"

// TestD3B_R1_T2BelowT1NeedsTwo verifies that a single-port rule
// belongs to T1 alone, so with T2 < T1 a leading port that clears T2 but not
// T1 still yields the smallest k with 2 ≤ k, never a one-rule top-k set.
func TestD3B_R1_T2BelowT1NeedsTwo(t *testing.T) {
	d3bRestoreTopK(t)
	SetXDropTopKConfig(60, 8)
	m := d3aMock(t)
	s := d3aNewStore("pps", 50000)
	a := d3aAttack("udp", "198.51.100.7", true)
	fa := d3aFA(t, s, a, d3bRows(17, 0, d3bDst(7901, 700, 7902, 200, 7903, 100)...))
	r := d3bExecute(t, m, s, a, v3Action(82, d3bDstTpl), fa)
	d3bCheckTopK(t, r, a, 82, d3bWant{dim: "dst_port", ports: []int{7901, 7902}, pct: 90, absent: []string{"rate_limit"}})
}
