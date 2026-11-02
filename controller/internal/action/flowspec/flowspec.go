// Package flowspec renders BGP Flowspec announcements for the routing vendors
// xSight targets. It is deliberately free of I/O and subprocesses: callers hand
// a rule to a renderer and receive the exact CLI lines to feed the device.
//
// FRR is the reference implementation because the Controller already drives it
// through vtysh for RTBH. The other vendors are expressed as editable templates
// because their exact Flowspec grammar drifts between releases; the operator can
// override a template without touching Go code.
package flowspec

import (
	"fmt"
	"strconv"
	"strings"
)

// Vendor selects the CLI dialect.
type Vendor string

const (
	VendorFRR     Vendor = "frr"
	VendorCisco   Vendor = "cisco_xr"
	VendorJuniper Vendor = "juniper"
	VendorArista  Vendor = "arista"
)

// Action is the terminal treatment for matched traffic.
type Action string

const (
	ActionDrop      Action = "drop"
	ActionRateLimit Action = "rate-limit"
)

// Rule is the vendor-neutral description of one Flowspec entry.
//
// Only the fields that are set are rendered; an unset port or protocol yields a
// broader match, so callers should set every field they can defend.
type Rule struct {
	// Name is the stable identifier used for withdraw and for logs. Required.
	Name string
	// Prefix is the destination prefix, e.g. 198.51.100.7/32. Required.
	Prefix string
	// Protocol is the IP protocol number (6=TCP, 17=UDP); nil omits the match.
	Protocol *uint8
	// DstPort / SrcPort are TCP/UDP ports; nil omits the match.
	DstPort *uint16
	SrcPort *uint16
	// Action is drop or rate-limit. Empty defaults to drop.
	Action Action
	// RateLimit is bytes per second; required when Action is rate-limit.
	RateLimit uint64
}

// ParseVendor normalizes operator input to a supported Vendor. An empty
// string selects FRR, matching the controller's default execution target.
func ParseVendor(s string) (Vendor, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "frr":
		return VendorFRR, nil
	case "cisco", "cisco_xr", "ios_xr":
		return VendorCisco, nil
	case "juniper", "junos":
		return VendorJuniper, nil
	case "arista", "eos":
		return VendorArista, nil
	}
	return "", fmt.Errorf("flowspec: unsupported vendor %q (want frr, cisco_xr, juniper, arista)", s)
}

// Validate reports whether the rule can be rendered.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("flowspec: rule name is required")
	}
	if strings.TrimSpace(r.Prefix) == "" {
		return fmt.Errorf("flowspec: destination prefix is required")
	}
	act := r.Action
	if act == "" {
		act = ActionDrop
	}
	if act != ActionDrop && act != ActionRateLimit {
		return fmt.Errorf("flowspec: unsupported action %q", r.Action)
	}
	if act == ActionRateLimit && r.RateLimit == 0 {
		return fmt.Errorf("flowspec: rate-limit action requires a positive rate")
	}
	return nil
}

func (r Rule) action() Action {
	if r.Action == "" {
		return ActionDrop
	}
	return r.Action
}

// Render returns the CLI lines that install the rule on the given vendor.
func Render(v Vendor, r Rule) ([]string, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	switch v {
	case VendorFRR, "":
		return renderFRR(r), nil
	case VendorCisco, VendorJuniper, VendorArista:
		return renderTemplate(v, r)
	default:
		return nil, fmt.Errorf("flowspec: unknown vendor %q", v)
	}
}

// RenderWithdraw returns the CLI lines that remove the rule.
func RenderWithdraw(v Vendor, r Rule) ([]string, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	switch v {
	case VendorFRR, "":
		return withdrawFRR(r), nil
	case VendorCisco, VendorJuniper, VendorArista:
		return withdrawTemplate(v, r)
	default:
		return nil, fmt.Errorf("flowspec: unknown vendor %q", v)
	}
}

func renderFRR(r Rule) []string {
	lines := []string{
		"configure terminal",
		"flowspec",
		fmt.Sprintf("flow spec ipv4 %s permit", r.Name),
		fmt.Sprintf(" match destination %s", r.Prefix),
	}
	if r.Protocol != nil {
		lines = append(lines, fmt.Sprintf(" match protocol %s", protoName(*r.Protocol)))
	}
	if r.SrcPort != nil {
		lines = append(lines, fmt.Sprintf(" match source-port %d", *r.SrcPort))
	}
	if r.DstPort != nil {
		lines = append(lines, fmt.Sprintf(" match destination-port %d", *r.DstPort))
	}
	if r.action() == ActionRateLimit {
		lines = append(lines, fmt.Sprintf(" then actions rate-limit %d", r.RateLimit))
	} else {
		lines = append(lines, " then actions drop")
	}
	lines = append(lines, "exit")
	return lines
}

func withdrawFRR(r Rule) []string {
	return []string{
		"configure terminal",
		"flowspec",
		fmt.Sprintf("no flow spec ipv4 %s", r.Name),
		"exit",
	}
}

// templateFor returns the announce/withdraw templates for a vendor. Placeholders
// are substituted literally; unset optional matches become empty lines and are
// dropped, which keeps a vendor template readable even when a field is absent.
func templateFor(v Vendor) (announce, withdraw []string) {
	switch v {
	case VendorCisco:
		return []string{
				"configure terminal",
				"flowspec",
				" flow {name}",
				"  match destination-address {prefix}",
				"  match protocol {protocol}",
				"  match source-port eq {src_port}",
				"  match destination-port eq {dst_port}",
				"  action {action_cli}",
				" !",
				"end",
			}, []string{
				"configure terminal",
				"flowspec",
				" no flow {name}",
				" !",
				"end",
			}
	case VendorJuniper:
		return []string{
				"configure",
				"set routing-options flow route {name} match destination {prefix}",
				"set routing-options flow route {name} match protocol {protocol}",
				"set routing-options flow route {name} match source-port {src_port}",
				"set routing-options flow route {name} match destination-port {dst_port}",
				"set routing-options flow route {name} then {action_cli}",
				"commit",
			}, []string{
				"configure",
				"delete routing-options flow route {name}",
				"commit",
			}
	case VendorArista:
		return []string{
				"configure terminal",
				"ipv4 access-list {name}",
				"  permit ip {prefix} any",
				"  action {action_cli}",
				"exit",
			}, []string{
				"configure terminal",
				"no ipv4 access-list {name}",
			}
	}
	return nil, nil
}

func renderTemplate(v Vendor, r Rule) ([]string, error) {
	announce, _ := templateFor(v)
	if announce == nil {
		return nil, fmt.Errorf("flowspec: no template for vendor %q", v)
	}
	return substitute(announce, r), nil
}

func withdrawTemplate(v Vendor, r Rule) ([]string, error) {
	_, withdraw := templateFor(v)
	if withdraw == nil {
		return nil, fmt.Errorf("flowspec: no template for vendor %q", v)
	}
	return substitute(withdraw, r), nil
}

func substitute(lines []string, r Rule) []string {
	act := "drop"
	if r.action() == ActionRateLimit {
		act = fmt.Sprintf("rate-limit %d", r.RateLimit)
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.ReplaceAll(line, "{name}", r.Name)
		line = strings.ReplaceAll(line, "{prefix}", r.Prefix)
		line = strings.ReplaceAll(line, "{protocol}", protoNamePtr(r.Protocol))
		line = strings.ReplaceAll(line, "{src_port}", portPtr(r.SrcPort))
		line = strings.ReplaceAll(line, "{dst_port}", portPtr(r.DstPort))
		line = strings.ReplaceAll(line, "{action_cli}", act)
		// Drop matches that rendered empty (e.g. "match protocol " with no value).
		if strings.HasSuffix(strings.TrimSpace(line), "match protocol") ||
			strings.HasSuffix(strings.TrimSpace(line), "match source-port") ||
			strings.HasSuffix(strings.TrimSpace(line), "match destination-port") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func protoNamePtr(p *uint8) string {
	if p == nil {
		return ""
	}
	return protoName(*p)
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	default:
		return strconv.Itoa(int(p))
	}
}

func portPtr(p *uint16) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(int(*p))
}
