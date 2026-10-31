package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// Unimplemented methods remain nil: an unexpected handler path must fail the harness.
type feMemory struct {
	store.Store
	users         map[int]store.User
	audit         map[int]store.AuditLog
	prefixes      map[int]store.WatchPrefix
	templates     map[int]store.ThresholdTemplate
	rules         map[int]store.Threshold
	responses     map[int]store.Response
	actions       map[int]store.ResponseAction
	conditions    map[int]store.ActionPrecondition
	targets       map[int][]int
	nodes         map[string]store.Node
	announcements map[int]store.BGPAnnouncement
	webhook       map[int]store.WebhookConnector
	shell         map[int]store.ShellConnector
	bgp           map[int]store.BGPConnector
	xdrop         map[int]store.XDropConnector
	listeners     map[int]store.FlowListener
	sources       map[int]store.FlowSource
	config        store.DynDetectConfig
	seq           map[string]int
}

func feError(code string) error { return &pgconn.PgError{Code: code} }
func (m *feMemory) next(table string) int {
	m.seq[table]++
	return m.seq[table]
}
func feGet[T any](rows map[int]T, id int) (*T, error) {
	v, ok := rows[id]
	if !ok {
		return nil, fmt.Errorf("row %d: %w", id, pgx.ErrNoRows)
	}
	// Repository reads own their pointers; binding a failed UPDATE must not mutate stored rows.
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var copy T
	if err := json.Unmarshal(raw, &copy); err != nil {
		panic(err)
	}
	if connector, ok := any(&copy).(*store.XDropConnector); ok {
		connector.APIKey = any(v).(store.XDropConnector).APIKey
	}
	return &copy, nil
}
func feAll[T any](rows map[int]T) []T {
	var ids []int
	for id := range rows {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var out []T
	for _, id := range ids {
		out = append(out, rows[id])
	}
	return out
}
func feExists[T any](rows map[int]T, id *int) bool {
	if id == nil {
		return true
	}
	_, ok := rows[*id]
	return ok
}
func feDecimal(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// Only the supplied PG corpus calibrates input/output compatibility.
func feCIDR(raw string) (string, error) {
	address, width, explicit := strings.Cut(raw, "/")
	ipv6 := strings.Contains(address, ":")
	var addr netip.Addr
	mask := 128
	if ipv6 {
		var err error
		addr, err = netip.ParseAddr(address)
		if err != nil || !addr.Is6() || addr.Zone() != "" || explicit && len(width) > 1 && width[0] == '0' {
			return "", feError("22P02")
		}
	} else {
		parts := strings.Split(address, ".")
		if len(parts) > 4 {
			return "", feError("22P02")
		}
		var octets [4]byte
		for i, p := range parts {
			n, ok := feDecimal(p)
			if !ok || n > 255 {
				return "", feError("22P02")
			}
			octets[i] = byte(n)
		}
		addr = netip.AddrFrom4(octets)
		switch {
		case octets[0] < 128:
			mask = 8
		case octets[0] < 192:
			mask = 16
		case octets[0] < 224:
			mask = 24
		case octets[0] < 240:
			mask = 4
		default:
			mask = 32
		}
		if len(parts) != 1 || mask != 4 {
			mask = max(mask, len(parts)*8)
		}
	}
	if explicit {
		var ok bool
		mask, ok = feDecimal(width)
		if !ok {
			return "", feError("22P02")
		}
	}
	p := netip.PrefixFrom(addr, mask)
	if !p.IsValid() || p != p.Masked() {
		return "", feError("22P02")
	}
	text := addr.String()
	if ipv6 {
		text = feIPv6Text(addr.As16())
	}
	return text + "/" + strconv.Itoa(mask), nil
}

func feIPv6Text(bytes [16]byte) string {
	var groups [8]int
	for i := range groups {
		groups[i] = int(bytes[2*i])<<8 | int(bytes[2*i+1])
	}
	if groups[0] == 0 && groups[1] == 0 && groups[2] == 0 && groups[3] == 0 && groups[4] == 0 &&
		(groups[5] == 0xffff || groups[5] == 0 && groups[6] != 0) {
		head := "::"
		if groups[5] == 0xffff {
			head = "::ffff:"
		}
		return fmt.Sprintf("%s%d.%d.%d.%d", head, bytes[12], bytes[13], bytes[14], bytes[15])
	}
	best, length := -1, 1
	for i := 0; i < len(groups); i++ {
		if groups[i] != 0 {
			continue
		}
		end := i
		for end < len(groups) && groups[end] == 0 {
			end++
		}
		if end-i > length {
			best, length = i, end-i
		}
		i = end - 1
	}
	parts := make([]string, len(groups))
	for i, n := range groups {
		parts[i] = strconv.FormatInt(int64(n), 16)
	}
	if best < 0 {
		return strings.Join(parts, ":")
	}
	return strings.Join(parts[:best], ":") + "::" + strings.Join(parts[best+length:], ":")
}
func feNullOrder(a, b *int) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return 1
	}
	if b == nil {
		return -1
	}
	return *a - *b
}
func feRuleLess(a, b store.Threshold) bool {
	if n := feNullOrder(a.PrefixID, b.PrefixID); n != 0 {
		return n < 0
	}
	if n := feNullOrder(a.TemplateID, b.TemplateID); n != 0 {
		return n < 0
	}
	return a.Decoder < b.Decoder
}

type fePrefix struct {
	store.PrefixRepo
	m *feMemory
}

func (m *feMemory) Prefixes() store.PrefixRepo { return &fePrefix{m: m} }
func (r *fePrefix) List(context.Context) ([]store.WatchPrefix, error) {
	rows := feAll(r.m.prefixes)
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Prefix < rows[j].Prefix })
	return rows, nil
}
func (r *fePrefix) ListTree(ctx context.Context) ([]store.WatchPrefix, error) { return r.List(ctx) }
func (r *fePrefix) Get(_ context.Context, id int) (*store.WatchPrefix, error) {
	return feGet(r.m.prefixes, id)
}
func (r *fePrefix) Create(_ context.Context, p *store.WatchPrefix) (int, error) {
	// $1::CIDR is evaluated before the row defaults (including nextval).
	prefix, err := feCIDR(p.Prefix)
	if err != nil {
		return 0, err
	}
	id := r.m.next("prefix")
	if !feExists(r.m.templates, p.ThresholdTemplateID) {
		return 0, feError("23503")
	}
	v := *p
	v.ID, v.Prefix, v.CreatedAt = id, prefix, time.Now()
	r.m.prefixes[id] = v
	return id, nil
}
func (r *fePrefix) Update(_ context.Context, p *store.WatchPrefix) error {
	prefix, err := feCIDR(p.Prefix)
	if err != nil {
		return err
	}
	if !feExists(r.m.templates, p.ThresholdTemplateID) {
		return feError("23503")
	}
	v := *p
	v.Prefix = prefix
	r.m.prefixes[p.ID] = v
	return nil
}
func (r *fePrefix) Delete(_ context.Context, id int) error {
	delete(r.m.prefixes, id)
	for key, p := range r.m.prefixes {
		if p.ParentID != nil && *p.ParentID == id {
			p.ParentID = nil
			r.m.prefixes[key] = p
		}
	}
	for key, t := range r.m.rules {
		if t.PrefixID != nil && *t.PrefixID == id {
			delete(r.m.rules, key)
		}
	}
	return nil
}

type feTemplate struct {
	store.ThresholdTemplateRepo
	m *feMemory
}

func (m *feMemory) ThresholdTemplates() store.ThresholdTemplateRepo { return &feTemplate{m: m} }
func (r *feTemplate) Get(_ context.Context, id int) (*store.ThresholdTemplate, error) {
	return feGet(r.m.templates, id)
}
func (r *feTemplate) List(ctx context.Context) ([]store.ThresholdTemplate, error) {
	rows := feAll(r.m.templates)
	for i := range rows {
		rules, _ := r.ListRules(ctx, rows[i].ID)
		prefixes, _ := r.ListPrefixesUsing(ctx, rows[i].ID)
		rows[i].RuleCount, rows[i].PrefixCount = len(rules), len(prefixes)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}
func (r *feTemplate) constraint(t *store.ThresholdTemplate) error {
	for _, old := range r.m.templates {
		if old.ID != t.ID && old.Name == t.Name {
			return feError("23505")
		}
	}
	if !feExists(r.m.responses, t.ResponseID) {
		return feError("23503")
	}
	return nil
}
func (r *feTemplate) Create(_ context.Context, t *store.ThresholdTemplate) (int, error) {
	id := r.m.next("template")
	if err := r.constraint(t); err != nil {
		return 0, err
	}
	v := *t
	v.ID, v.CreatedAt, v.UpdatedAt = id, time.Now(), time.Now()
	v.RuleCount, v.PrefixCount = 0, 0
	r.m.templates[id] = v
	return id, nil
}
func (r *feTemplate) Update(_ context.Context, t *store.ThresholdTemplate) error {
	if err := r.constraint(t); err != nil {
		return err
	}
	v := *t
	v.UpdatedAt = time.Now()
	r.m.templates[t.ID] = v
	return nil
}
func (r *feTemplate) Delete(_ context.Context, id int) error {
	for _, p := range r.m.prefixes {
		if p.ThresholdTemplateID != nil && *p.ThresholdTemplateID == id {
			return feError("23503")
		}
	}
	delete(r.m.templates, id)
	for key, t := range r.m.rules {
		if t.TemplateID != nil && *t.TemplateID == id {
			delete(r.m.rules, key)
		}
	}
	return nil
}
func (r *feTemplate) Duplicate(ctx context.Context, id int, name string) (int, error) {
	t, err := r.Get(ctx, id)
	if err != nil {
		return 0, err
	}
	t.ID, t.Name = 0, name
	newID, err := r.Create(ctx, t)
	if err != nil {
		return 0, err
	}
	for _, rule := range feAll(r.m.rules) {
		if rule.TemplateID == nil || *rule.TemplateID != id {
			continue
		}
		rule.ID, rule.TemplateID = 0, &newID
		if _, err := r.m.Thresholds().Create(ctx, &rule); err != nil {
			_ = r.Delete(ctx, newID)
			return 0, err
		}
	}
	return newID, nil
}
func (r *feTemplate) ListRules(_ context.Context, id int) ([]store.Threshold, error) {
	var rows []store.Threshold
	for _, t := range feAll(r.m.rules) {
		if t.TemplateID != nil && *t.TemplateID == id {
			rows = append(rows, t)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Decoder != rows[j].Decoder {
			return rows[i].Decoder < rows[j].Decoder
		}
		return rows[i].Unit < rows[j].Unit
	})
	return rows, nil
}
func (r *feTemplate) ListPrefixesUsing(ctx context.Context, id int) ([]store.WatchPrefix, error) {
	all, _ := r.m.Prefixes().List(ctx)
	var rows []store.WatchPrefix
	for _, p := range all {
		if p.ThresholdTemplateID != nil && *p.ThresholdTemplateID == id {
			rows = append(rows, p)
		}
	}
	return rows, nil
}

type feThreshold struct {
	store.ThresholdRepo
	m *feMemory
}

func (m *feMemory) Thresholds() store.ThresholdRepo { return &feThreshold{m: m} }
func (r *feThreshold) List(context.Context) ([]store.Threshold, error) {
	rows := feAll(r.m.rules)
	sort.SliceStable(rows, func(i, j int) bool { return feRuleLess(rows[i], rows[j]) })
	return rows, nil
}
func (r *feThreshold) Get(_ context.Context, id int) (*store.Threshold, error) {
	return feGet(r.m.rules, id)
}
func (r *feThreshold) constraint(t *store.Threshold) error {
	if !feExists(r.m.prefixes, t.PrefixID) {
		return feError("23503")
	}
	if !feExists(r.m.templates, t.TemplateID) {
		return feError("23503")
	}
	if !feExists(r.m.responses, t.ResponseID) {
		return feError("23503")
	}
	// Authorization #1: the two partial unique indexes; UPDATE excludes its own row.
	for _, old := range r.m.rules {
		if old.ID == t.ID || old.Decoder != t.Decoder || old.Unit != t.Unit || old.Direction != t.Direction || old.Domain != t.Domain {
			continue
		}
		templateKey := t.TemplateID != nil && old.TemplateID != nil && *t.TemplateID == *old.TemplateID
		prefixKey := t.PrefixID != nil && old.PrefixID != nil && *t.PrefixID == *old.PrefixID
		if templateKey || prefixKey {
			return feError("23505")
		}
	}
	return nil
}
func (r *feThreshold) Create(_ context.Context, t *store.Threshold) (int, error) {
	id := r.m.next("rule")
	if err := r.constraint(t); err != nil {
		return 0, err
	}
	v := *t
	v.ID, v.CreatedAt = id, time.Now()
	r.m.rules[id] = v
	return id, nil
}
func (r *feThreshold) Update(_ context.Context, t *store.Threshold) error {
	if err := r.constraint(t); err != nil {
		return err
	}
	r.m.rules[t.ID] = *t
	return nil
}
func (r *feThreshold) Delete(_ context.Context, id int) error { delete(r.m.rules, id); return nil }

type feResponse struct {
	store.ResponseRepo
	m *feMemory
}

func (m *feMemory) Responses() store.ResponseRepo { return &feResponse{m: m} }
func (r *feResponse) List(context.Context) ([]store.Response, error) {
	rows := feAll(r.m.responses)
	for i := range rows {
		for _, a := range r.m.actions {
			if a.ResponseID == rows[i].ID {
				rows[i].ActionCount++
			}
		}
		for _, t := range r.m.templates {
			if t.ResponseID != nil && *t.ResponseID == rows[i].ID {
				rows[i].BoundTemplateCount++
			}
		}
	}
	return rows, nil
}
func (r *feResponse) Get(_ context.Context, id int) (*store.Response, error) {
	return feGet(r.m.responses, id)
}
func (r *feResponse) Create(_ context.Context, v *store.Response) (int, error) {
	id := r.m.next("response")
	row := *v
	row.ID, row.CreatedAt = id, time.Now()
	r.m.responses[id] = row
	return id, nil
}
func (r *feResponse) Update(_ context.Context, v *store.Response) error {
	row := *v
	row.CreatedAt = r.m.responses[v.ID].CreatedAt
	r.m.responses[v.ID] = row
	return nil
}
func (r *feResponse) Delete(ctx context.Context, id int) error {
	delete(r.m.responses, id)
	for key, a := range r.m.actions {
		if a.ResponseID == id {
			_ = r.DeleteAction(ctx, key)
		}
	}
	for key, t := range r.m.templates {
		if t.ResponseID != nil && *t.ResponseID == id {
			t.ResponseID = nil
			r.m.templates[key] = t
		}
	}
	for key, t := range r.m.rules {
		if t.ResponseID != nil && *t.ResponseID == id {
			t.ResponseID = nil
			r.m.rules[key] = t
		}
	}
	return nil
}
func (r *feResponse) ListActions(_ context.Context, id int) ([]store.ResponseAction, error) {
	var rows []store.ResponseAction
	for _, a := range feAll(r.m.actions) {
		if a.ResponseID == id {
			rows = append(rows, a)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].TriggerPhase != rows[j].TriggerPhase {
			return rows[i].TriggerPhase < rows[j].TriggerPhase
		}
		return rows[i].Priority < rows[j].Priority
	})
	return rows, nil
}
func (r *feResponse) GetAction(_ context.Context, id int) (*store.ResponseAction, error) {
	a, err := feGet(r.m.actions, id)
	if err != nil {
		return nil, err
	}
	// No mutable RawMessage aliases escape the repository.
	a.Config = slices.Clone(a.Config)
	a.Preconditions = slices.Clone(a.Preconditions)
	a.XDropCustomPayload = slices.Clone(a.XDropCustomPayload)
	return a, nil
}
func (r *feResponse) CreateAction(_ context.Context, a *store.ResponseAction) (int, error) {
	id := r.m.next("action")
	if _, ok := r.m.responses[a.ResponseID]; !ok {
		return 0, feError("23503")
	}
	v := *a
	v.ID = id
	r.m.actions[id] = v
	return id, nil
}
func (r *feResponse) UpdateAction(_ context.Context, a *store.ResponseAction) error {
	r.m.actions[a.ID] = *a
	return nil
}
func (r *feResponse) SetPairedWith(_ context.Context, id int, pair *int) error {
	a := r.m.actions[id]
	a.PairedWith = pair
	r.m.actions[id] = a
	return nil
}
func (r *feResponse) DeleteAction(_ context.Context, id int) error {
	delete(r.m.actions, id)
	delete(r.m.targets, id)
	for key, c := range r.m.conditions {
		if c.ActionID == id {
			delete(r.m.conditions, key)
		}
	}
	for key, a := range r.m.actions {
		if a.PairedWith != nil && *a.PairedWith == id {
			a.PairedWith = nil
			r.m.actions[key] = a
		}
	}
	return nil
}

type fePrecondition struct {
	store.PreconditionRepo
	m *feMemory
}

func (m *feMemory) Preconditions() store.PreconditionRepo { return &fePrecondition{m: m} }
func (r *fePrecondition) List(_ context.Context, id int) ([]store.ActionPrecondition, error) {
	var rows []store.ActionPrecondition
	for _, p := range feAll(r.m.conditions) {
		if p.ActionID == id {
			rows = append(rows, p)
		}
	}
	return rows, nil
}
func (r *fePrecondition) ReplaceAll(_ context.Context, id int, rows []store.ActionPrecondition) error {
	// Transaction rollback restores DELETE/INSERT rows, but never nextval.
	var next []store.ActionPrecondition
	for _, p := range rows {
		p.ID = r.m.next("condition")
		if _, ok := r.m.actions[id]; !ok {
			return feError("23503")
		}
		p.ActionID, p.CreatedAt = id, time.Now()
		next = append(next, p)
	}
	for key, p := range r.m.conditions {
		if p.ActionID == id {
			delete(r.m.conditions, key)
		}
	}
	for _, p := range next {
		r.m.conditions[p.ID] = p
	}
	return nil
}

type feTargets struct {
	store.XDropTargetRepo
	m *feMemory
}

func (m *feMemory) XDropTargets() store.XDropTargetRepo { return &feTargets{m: m} }
func (r *feTargets) List(_ context.Context, id int) ([]store.XDropConnector, error) {
	var rows []store.XDropConnector
	for _, c := range feAll(r.m.xdrop) {
		if slices.Contains(r.m.targets[id], c.ID) {
			rows = append(rows, c)
		}
	}
	return rows, nil
}
func (r *feTargets) Set(_ context.Context, id int, ids []int) error {
	r.m.targets[id] = slices.Clone(ids)
	return nil
}

type feDyn struct {
	store.DynDetectRepo
	m *feMemory
}

func (m *feMemory) DynDetect() store.DynDetectRepo { return &feDyn{m: m} }
func (r *feDyn) GetConfig(context.Context) (*store.DynDetectConfig, error) {
	c := r.m.config
	return &c, nil
}
func (r *feDyn) UpdateConfig(_ context.Context, c *store.DynDetectConfig) error {
	r.m.config = *c
	return nil
}

type feNode struct {
	store.NodeRepo
	m *feMemory
}

func (m *feMemory) Nodes() store.NodeRepo { return &feNode{m: m} }
func (r *feNode) Get(_ context.Context, id string) (*store.Node, error) {
	n, ok := r.m.nodes[id]
	if !ok {
		return nil, fmt.Errorf("node %s: %w", id, pgx.ErrNoRows)
	}
	return &n, nil
}
func (r *feNode) Create(_ context.Context, n *store.Node) error {
	if _, ok := r.m.nodes[n.ID]; ok {
		return feError("23505")
	}
	v := *n
	v.CreatedAt, v.UpdatedAt = time.Now(), time.Now()
	r.m.nodes[n.ID] = v
	return nil
}
func (r *feNode) Delete(_ context.Context, id string) error { delete(r.m.nodes, id); return nil }

type feListeners struct {
	store.FlowListenerRepo
	m *feMemory
}

func (m *feMemory) FlowListeners() store.FlowListenerRepo { return &feListeners{m: m} }
func (r *feListeners) List(_ context.Context, node string) ([]store.FlowListener, error) {
	var rows []store.FlowListener
	for _, v := range feAll(r.m.listeners) {
		if v.NodeID == node {
			rows = append(rows, v)
		}
	}
	return rows, nil
}
func (r *feListeners) Get(_ context.Context, id int) (*store.FlowListener, error) {
	return feGet(r.m.listeners, id)
}
func (r *feListeners) unique(v *store.FlowListener) error {
	for _, old := range r.m.listeners {
		if old.ID != v.ID && old.NodeID == v.NodeID && old.ListenAddress == v.ListenAddress {
			return feError("23505")
		}
	}
	return nil
}
func (r *feListeners) Create(_ context.Context, v *store.FlowListener) (int, error) {
	id := r.m.next("listener")
	if err := r.unique(v); err != nil {
		return 0, err
	}
	copy := *v
	copy.ID, copy.CreatedAt = id, time.Now()
	r.m.listeners[id] = copy
	return id, nil
}
func (r *feListeners) Update(_ context.Context, v *store.FlowListener) error {
	if err := r.unique(v); err != nil {
		return err
	}
	copy := *v
	copy.CreatedAt = r.m.listeners[v.ID].CreatedAt
	r.m.listeners[v.ID] = copy
	return nil
}
func (r *feListeners) Delete(_ context.Context, id int) error {
	delete(r.m.listeners, id)
	for sid, source := range r.m.sources {
		if source.ListenerID == id {
			delete(r.m.sources, sid)
		}
	}
	return nil
}

type feSources struct {
	store.FlowSourceRepo
	m *feMemory
}

func (m *feMemory) FlowSources() store.FlowSourceRepo { return &feSources{m: m} }
func (r *feSources) List(_ context.Context, listener int) ([]store.FlowSource, error) {
	var rows []store.FlowSource
	for _, v := range feAll(r.m.sources) {
		if v.ListenerID == listener {
			rows = append(rows, v)
		}
	}
	return rows, nil
}
func (r *feSources) Get(_ context.Context, id int) (*store.FlowSource, error) {
	return feGet(r.m.sources, id)
}
func (r *feSources) normalized(v *store.FlowSource) (store.FlowSource, error) {
	copy := *v
	text, err := feINET(v.DeviceIP)
	if err != nil {
		return copy, err
	}
	copy.DeviceIP = text
	for _, old := range r.m.sources {
		if old.ID != v.ID && old.ListenerID == v.ListenerID && old.DeviceIP == text {
			return copy, feError("23505")
		}
	}
	return copy, nil
}
func (r *feSources) Create(_ context.Context, v *store.FlowSource) (int, error) {
	if v.SampleRate < -2147483648 || v.SampleRate > 2147483647 {
		return 0, fmt.Errorf("sample_rate out of int32 range")
	}
	id := r.m.next("source")
	copy, err := r.normalized(v)
	if err != nil {
		return 0, err
	}
	copy.ID, copy.CreatedAt = id, time.Now()
	r.m.sources[id] = copy
	return id, nil
}
func (r *feSources) Update(_ context.Context, v *store.FlowSource) error {
	if v.SampleRate < -2147483648 || v.SampleRate > 2147483647 {
		return fmt.Errorf("sample_rate out of int32 range")
	}
	copy, err := r.normalized(v)
	if err != nil {
		return err
	}
	copy.CreatedAt = r.m.sources[v.ID].CreatedAt
	r.m.sources[v.ID] = copy
	return nil
}
func (r *feSources) Delete(_ context.Context, id int) error {
	delete(r.m.sources, id)
	return nil
}

type feUsers struct {
	store.UserRepo
	m *feMemory
}

func (m *feMemory) Users() store.UserRepo                     { return &feUsers{m: m} }
func (r *feUsers) List(context.Context) ([]store.User, error) { return feAll(r.m.users), nil }
func (r *feUsers) Get(_ context.Context, id int) (*store.User, error) {
	row, ok := r.m.users[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return &row, nil
}
func (r *feUsers) Create(_ context.Context, row *store.User) (int, error) {
	id := r.m.next("user")
	for _, existing := range r.m.users {
		if existing.Username == row.Username {
			return 0, feError("23505")
		}
	}
	copy := *row
	copy.ID, copy.CreatedAt, copy.UpdatedAt = id, time.Now(), time.Now()
	r.m.users[id] = copy
	return id, nil
}
func (r *feUsers) Update(_ context.Context, row *store.User) error {
	if r.lastAdmin(row.ID) && !(row.Role == "admin" && row.Enabled) {
		return store.ErrLastAdmin
	}
	for id, existing := range r.m.users {
		if id != row.ID && existing.Username == row.Username {
			return feError("23505")
		}
	}
	if _, exists := r.m.users[row.ID]; exists {
		copy := *row
		copy.UpdatedAt = time.Now()
		r.m.users[row.ID] = copy
	}
	return nil
}
func (r *feUsers) Delete(_ context.Context, id int) error {
	if r.lastAdmin(id) {
		return store.ErrLastAdmin
	}
	delete(r.m.users, id)
	for key, row := range r.m.audit {
		if row.UserID != nil && *row.UserID == id {
			row.UserID = nil
			r.m.audit[key] = row
		}
	}
	return nil
}

func (r *feUsers) lastAdmin(id int) bool {
	old, exists := r.m.users[id]
	if !exists || old.Role != "admin" || !old.Enabled {
		return false
	}
	for otherID, row := range r.m.users {
		if otherID != id && row.Role == "admin" && row.Enabled {
			return false
		}
	}
	return true
}

type feAudit struct {
	store.AuditLogRepo
	m *feMemory
}

func (m *feMemory) AuditLog() store.AuditLogRepo               { return &feAudit{m: m} }
func (*feAudit) Create(context.Context, *store.AuditLog) error { return nil }
func (r *feAudit) List(_ context.Context, f store.AuditFilter) ([]store.AuditLog, error) {
	var rows []store.AuditLog
	for _, row := range r.m.audit {
		if f.EntityType != "" && row.EntityType != f.EntityType {
			continue
		}
		if f.UserID != nil && (row.UserID == nil || *row.UserID != *f.UserID) {
			continue
		}
		if f.TimeFrom != nil && row.CreatedAt.Before(*f.TimeFrom) {
			continue
		}
		if f.TimeTo != nil && row.CreatedAt.After(*f.TimeTo) {
			continue
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CreatedAt.After(rows[j].CreatedAt) })
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if f.Offset >= len(rows) {
		return nil, nil
	}
	rows = rows[f.Offset:]
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

type feAnnouncement struct {
	store.BGPAnnouncementRepo
	m *feMemory
}

func (m *feMemory) BGPAnnouncements() store.BGPAnnouncementRepo { return &feAnnouncement{m: m} }
func (r *feAnnouncement) Get(_ context.Context, id int) (*store.BGPAnnouncement, error) {
	a, ok := r.m.announcements[id]
	if !ok {
		return nil, nil
	}
	return &a, nil
}
func (r *feAnnouncement) Dismiss(_ context.Context, id int) error {
	a := r.m.announcements[id]
	if a.Status == "orphan" {
		a.Status = "dismissed"
		r.m.announcements[id] = a
	}
	return nil
}
func (r *feAnnouncement) Undismiss(_ context.Context, id int) error {
	a := r.m.announcements[id]
	if a.Status == "dismissed" || a.Status == "dismissed_on_upgrade" {
		a.Status = "orphan"
		r.m.announcements[id] = a
	}
	return nil
}

// Compile-time interface checks supplement the embedded-interface failure trap.
var _ store.Store = (*feMemory)(nil)

type feWebhook struct {
	store.WebhookConnectorRepo
	m *feMemory
}

func (m *feMemory) WebhookConnectors() store.WebhookConnectorRepo { return &feWebhook{m: m} }
func (r *feWebhook) List(context.Context) ([]store.WebhookConnector, error) {
	return feAll(r.m.webhook), nil
}
func (r *feWebhook) Get(_ context.Context, id int) (*store.WebhookConnector, error) {
	return feGet(r.m.webhook, id)
}

type feShell struct {
	store.ShellConnectorRepo
	m *feMemory
}

func (m *feMemory) ShellConnectors() store.ShellConnectorRepo           { return &feShell{m: m} }
func (r *feShell) List(context.Context) ([]store.ShellConnector, error) { return feAll(r.m.shell), nil }
func (r *feShell) Get(_ context.Context, id int) (*store.ShellConnector, error) {
	return feGet(r.m.shell, id)
}

type feBGP struct {
	store.BGPConnectorRepo
	m *feMemory
}

func (m *feMemory) BGPConnectors() store.BGPConnectorRepo           { return &feBGP{m: m} }
func (r *feBGP) List(context.Context) ([]store.BGPConnector, error) { return feAll(r.m.bgp), nil }
func (r *feBGP) Get(_ context.Context, id int) (*store.BGPConnector, error) {
	return feGet(r.m.bgp, id)
}

type feXDrop struct {
	store.XDropConnectorRepo
	m *feMemory
}

func (m *feMemory) XDropConnectors() store.XDropConnectorRepo           { return &feXDrop{m: m} }
func (r *feXDrop) List(context.Context) ([]store.XDropConnector, error) { return feAll(r.m.xdrop), nil }
func (r *feXDrop) Get(_ context.Context, id int) (*store.XDropConnector, error) {
	return feGet(r.m.xdrop, id)
}

// Initialize from seeded IDs on the first connector INSERT; failed INSERTs also consume nextval.
func feConnectorInit[T any](m *feMemory, table string, rows map[int]T) {
	if _, set := m.seq[table]; !set {
		for id := range rows {
			m.seq[table] = max(m.seq[table], id)
		}
	}
	if _, set := m.seq[table]; !set {
		m.seq[table] = 0
	}
}
func feConnectorNext[T any](m *feMemory, table string, rows map[int]T) int {
	feConnectorInit(m, table, rows)
	return m.next(table)
}
func feConnectorName[T any](rows map[int]T, id int, name string, get func(T) string) error {
	for key, row := range rows {
		if key != id && get(row) == name {
			return feError("23505")
		}
	}
	return nil
}

func (r *feWebhook) Create(_ context.Context, c *store.WebhookConnector) (int, error) {
	id := feConnectorNext(r.m, "webhook_connector", r.m.webhook)
	if err := feConnectorName(r.m.webhook, 0, c.Name, func(v store.WebhookConnector) string { return v.Name }); err != nil {
		return 0, err
	}
	v := *c
	v.ID, v.CreatedAt, v.UpdatedAt = id, time.Now(), time.Now()
	r.m.webhook[id] = v
	return id, nil
}
func (r *feWebhook) Update(_ context.Context, c *store.WebhookConnector) error {
	if err := feConnectorName(r.m.webhook, c.ID, c.Name, func(v store.WebhookConnector) string { return v.Name }); err != nil {
		return err
	}
	if old, exists := r.m.webhook[c.ID]; exists {
		v := *c
		v.CreatedAt, v.UpdatedAt = old.CreatedAt, time.Now()
		r.m.webhook[c.ID] = v
	}
	return nil
}
func (r *feWebhook) Delete(ctx context.Context, id int) error {
	feConnectorInit(r.m, "webhook_connector", r.m.webhook)
	n, _ := r.m.Responses().CountActionsByWebhookConnector(ctx, id)
	if n > 0 {
		return feError("23503")
	}
	delete(r.m.webhook, id)
	return nil
}

func (r *feShell) Create(_ context.Context, c *store.ShellConnector) (int, error) {
	id := feConnectorNext(r.m, "shell_connector", r.m.shell)
	if err := feConnectorName(r.m.shell, 0, c.Name, func(v store.ShellConnector) string { return v.Name }); err != nil {
		return 0, err
	}
	v := *c
	v.ID, v.CreatedAt, v.UpdatedAt = id, time.Now(), time.Now()
	r.m.shell[id] = v
	return id, nil
}
func (r *feShell) Update(_ context.Context, c *store.ShellConnector) error {
	if err := feConnectorName(r.m.shell, c.ID, c.Name, func(v store.ShellConnector) string { return v.Name }); err != nil {
		return err
	}
	if old, exists := r.m.shell[c.ID]; exists {
		v := *c
		v.CreatedAt, v.UpdatedAt = old.CreatedAt, time.Now()
		r.m.shell[c.ID] = v
	}
	return nil
}
func (r *feShell) Delete(ctx context.Context, id int) error {
	feConnectorInit(r.m, "shell_connector", r.m.shell)
	n, _ := r.m.Responses().CountActionsByShellConnector(ctx, id)
	if n > 0 {
		return feError("23503")
	}
	delete(r.m.shell, id)
	return nil
}

func (r *feBGP) Create(_ context.Context, c *store.BGPConnector) (int, error) {
	id := feConnectorNext(r.m, "bgp_connector", r.m.bgp)
	if err := feConnectorName(r.m.bgp, 0, c.Name, func(v store.BGPConnector) string { return v.Name }); err != nil {
		return 0, err
	}
	v := *c
	v.ID, v.CreatedAt, v.UpdatedAt = id, time.Now(), time.Now()
	r.m.bgp[id] = v
	return id, nil
}
func (r *feBGP) Update(_ context.Context, c *store.BGPConnector) error {
	if err := feConnectorName(r.m.bgp, c.ID, c.Name, func(v store.BGPConnector) string { return v.Name }); err != nil {
		return err
	}
	if old, exists := r.m.bgp[c.ID]; exists {
		v := *c
		v.CreatedAt, v.UpdatedAt = old.CreatedAt, time.Now()
		r.m.bgp[c.ID] = v
	}
	return nil
}
func (r *feBGP) Delete(ctx context.Context, id int) error {
	feConnectorInit(r.m, "bgp_connector", r.m.bgp)
	for key, a := range r.m.actions {
		if a.BGPConnectorID != nil && *a.BGPConnectorID == id {
			a.BGPConnectorID = nil
			r.m.actions[key] = a
		}
	}
	delete(r.m.bgp, id)
	return nil
}

func (r *feXDrop) Create(_ context.Context, c *store.XDropConnector) (int, error) {
	id := feConnectorNext(r.m, "xdrop_connector", r.m.xdrop)
	if err := feConnectorName(r.m.xdrop, 0, c.Name, func(v store.XDropConnector) string { return v.Name }); err != nil {
		return 0, err
	}
	v := *c
	v.ID, v.CreatedAt, v.UpdatedAt = id, time.Now(), time.Now()
	r.m.xdrop[id] = v
	return id, nil
}
func (r *feXDrop) Update(_ context.Context, c *store.XDropConnector) error {
	if err := feConnectorName(r.m.xdrop, c.ID, c.Name, func(v store.XDropConnector) string { return v.Name }); err != nil {
		return err
	}
	if old, exists := r.m.xdrop[c.ID]; exists {
		v := *c
		v.CreatedAt, v.UpdatedAt = old.CreatedAt, time.Now()
		r.m.xdrop[c.ID] = v
	}
	return nil
}
func (r *feXDrop) Delete(ctx context.Context, id int) error {
	feConnectorInit(r.m, "xdrop_connector", r.m.xdrop)
	for key, targets := range r.m.targets {
		r.m.targets[key] = slices.DeleteFunc(slices.Clone(targets), func(target int) bool { return target == id })
	}
	delete(r.m.xdrop, id)
	return nil
}

func (r *feResponse) CountActionsByWebhookConnector(_ context.Context, id int) (int, error) {
	count := 0
	for _, a := range r.m.actions {
		if a.WebhookConnectorID != nil && *a.WebhookConnectorID == id {
			count++
		}
	}
	return count, nil
}

func (r *feResponse) CountActionsByShellConnector(_ context.Context, id int) (int, error) {
	count := 0
	for _, a := range r.m.actions {
		if a.ShellConnectorID != nil && *a.ShellConnectorID == id {
			count++
		}
	}
	return count, nil
}

func (r *feResponse) CountActionsByBGPConnector(_ context.Context, id int) (int, error) {
	count := 0
	for _, a := range r.m.actions {
		if a.BGPConnectorID != nil && *a.BGPConnectorID == id {
			count++
		}
	}
	return count, nil
}

func (r *feTargets) CountByConnector(_ context.Context, id int) (int, error) {
	count := 0
	for _, targets := range r.m.targets {
		for _, target := range targets {
			if target == id {
				count++
			}
		}
	}
	return count, nil
}
func (r *feAnnouncement) CountLiveByConnector(_ context.Context, id int) (int, error) {
	count := 0
	for _, a := range r.m.announcements {
		if a.ConnectorID == id && slices.Contains([]string{"announcing", "active", "delayed", "withdrawing", "failed", "orphan"}, a.Status) {
			count++
		}
	}
	return count, nil
}

// This seed has no xdrop_active_rules table. Preserve the nil trap for all other methods.
type feXDropRules struct{ store.XDropActiveRuleRepo }

func (m *feMemory) XDropActiveRules() store.XDropActiveRuleRepo              { return &feXDropRules{} }
func (*feXDropRules) CountLiveByConnector(context.Context, int) (int, error) { return 0, nil }

func TestFEParityConnectorSequenceAfterDelete(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"webhook", "shell", "bgp", "xdrop"} {
		t.Run(kind, func(t *testing.T) {
			m := &feMemory{seq: map[string]int{},
				webhook: map[int]store.WebhookConnector{2: {ID: 2, Name: "seed"}},
				shell:   map[int]store.ShellConnector{2: {ID: 2, Name: "seed"}},
				bgp:     map[int]store.BGPConnector{2: {ID: 2, Name: "seed"}},
				xdrop:   map[int]store.XDropConnector{2: {ID: 2, Name: "seed"}},
			}
			var id int
			var err error
			switch kind {
			case "webhook":
				err = m.WebhookConnectors().Delete(ctx, 2)
				if err == nil {
					id, err = m.WebhookConnectors().Create(ctx, &store.WebhookConnector{Name: "new"})
				}
			case "shell":
				err = m.ShellConnectors().Delete(ctx, 2)
				if err == nil {
					id, err = m.ShellConnectors().Create(ctx, &store.ShellConnector{Name: "new"})
				}
			case "bgp":
				err = m.BGPConnectors().Delete(ctx, 2)
				if err == nil {
					id, err = m.BGPConnectors().Create(ctx, &store.BGPConnector{Name: "new"})
				}
			case "xdrop":
				err = m.XDropConnectors().Delete(ctx, 2)
				if err == nil {
					id, err = m.XDropConnectors().Create(ctx, &store.XDropConnector{Name: "new"})
				}
			}
			if err != nil || id != 3 {
				t.Fatalf("after deleting seeded maximum: id=%d err=%v want 3", id, err)
			}
		})
	}
}
