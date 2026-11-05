// Package l7store keeps a bounded, in-memory view of the layer-7 events that
// Nodes report over CriticalEventStream (HTTP floods, Slowloris build-ups and
// TLS ClientHello anomalies).
//
// Deliberately in-memory: these events are high-cardinality and short-lived,
// and the console polls the aggregate once per refresh. Persisting them would
// mean a new hypertable and a retention policy for data that is only useful
// while the attack is running. Totals therefore reset when the Controller
// restarts — the authoritative per-attack record stays in attacks/actions_log.
package l7store

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Event is one aggregated L7 observation window from a Node.
type Event struct {
	NodeID    string            `json:"node_id"`
	Type      string            `json:"type"`
	DstIP     string            `json:"dst_ip"`
	At        time.Time         `json:"at"`
	Counters  map[string]uint64 `json:"-"`
	Detail    Detail            `json:"detail"`
	Interface string            `json:"interface,omitempty"`
}

// Detail decomposes the flat counter map into the fields the console renders.
type Detail struct {
	Requests       uint64   `json:"requests,omitempty"`
	Methods        []string `json:"methods,omitempty"`
	Paths          []string `json:"paths,omitempty"`
	Handshakes     uint64   `json:"handshakes,omitempty"`
	SNIs           []string `json:"snis,omitempty"`
	MissingSNI     uint64   `json:"missing_sni,omitempty"`
	Connections    uint64   `json:"connections,omitempty"`
	UniqueSources  uint64   `json:"unique_sources,omitempty"`
	SampleSources  []string `json:"sample_sources,omitempty"`
	WindowSeconds  int      `json:"window_seconds,omitempty"`
	AlertThreshold uint64   `json:"alert_threshold,omitempty"`
}

// Target aggregates one destination across all event types.
type Target struct {
	DstIP     string    `json:"dst_ip"`
	HTTP      uint64    `json:"http"`
	TLS       uint64    `json:"tls"`
	Slowloris uint64    `json:"slowloris"`
	Total     uint64    `json:"total"`
	LastAt    time.Time `json:"last_at"`
}

// Point is one time bucket of the stacked chart.
type Point struct {
	At        time.Time `json:"at"`
	HTTP      uint64    `json:"http"`
	TLS       uint64    `json:"tls"`
	Slowloris uint64    `json:"slowloris"`
}

// Snapshot is the read model served to the console.
type Snapshot struct {
	GeneratedAt   time.Time          `json:"generated_at"`
	WindowMinutes int                `json:"window_minutes"`
	BucketSeconds int                `json:"bucket_seconds"`
	Totals        map[string]uint64  `json:"totals"`
	Rates         map[string]float64 `json:"rates_per_second"`
	Series        []Point            `json:"series"`
	Targets       []Target           `json:"targets"`
	Sources       []Counter          `json:"sources"`
	Nodes         []Counter          `json:"nodes"`
	// v4.0 anti-bot fingerprints: TLS JA3/JA4 digests and HTTP User-Agents
	// observed across the window, highest-count first.
	JA3        []Counter `json:"ja3"`
	JA4        []Counter `json:"ja4"`
	UserAgents []Counter `json:"user_agents"`
	Recent     []Event   `json:"recent"`
	Dropped    uint64    `json:"dropped"`
}

// Counter is a generic label/value pair used for top-N lists.
type Counter struct {
	Label string `json:"label"`
	Count uint64 `json:"count"`
}

type bucket struct {
	at        time.Time
	http      uint64
	tls       uint64
	slowloris uint64
}

// Store is a concurrency-safe ring of L7 events plus a per-bucket time series.
type Store struct {
	mu          sync.Mutex
	maxEvents   int
	maxTargets  int
	maxSeries   int
	bucketWidth time.Duration
	seriesSpan  time.Duration

	events  []Event
	targets map[string]*Target
	sources map[string]uint64
	nodes   map[string]uint64
	ja3     map[string]uint64
	ja4     map[string]uint64
	uas     map[string]uint64
	series  []bucket
	dropped uint64
}

// New builds a Store. maxEvents bounds the recent-event ring; a zero or
// negative value selects 5000.
func New(maxEvents int) *Store {
	if maxEvents <= 0 {
		maxEvents = 5000
	}
	return &Store{
		maxEvents:   maxEvents,
		maxTargets:  512,
		maxSeries:   240,
		bucketWidth: time.Minute,
		seriesSpan:  4 * time.Hour,
		targets:     make(map[string]*Target),
		sources:     make(map[string]uint64),
		nodes:       make(map[string]uint64),
		ja3:         make(map[string]uint64),
		ja4:         make(map[string]uint64),
		uas:         make(map[string]uint64),
	}
}

// Kind names for the event types the Node emits. They match the l7 decoder
// names so the console can label them without a translation table.
const (
	KindHTTPFlood  = "l7_http_flood"
	KindTLSAnomaly = "l7_tls_anomaly"
	KindSlowloris  = "l7_slowloris"
)

func kindOf(eventType string) string {
	t := strings.ToLower(eventType)
	switch {
	case strings.Contains(t, "slowloris"):
		return KindSlowloris
	case strings.Contains(t, "tls"):
		return KindTLSAnomaly
	case strings.Contains(t, "http"):
		return KindHTTPFlood
	default:
		return eventType
	}
}

// parseDetail splits the Node's flat counter map (keys like "http_path:/login",
// "src:203.0.113.9") back into structured detail.
func parseDetail(counters map[string]uint64) Detail {
	var d Detail
	for k, v := range counters {
		switch {
		case strings.HasPrefix(k, "http_method:"):
			d.Methods = append(d.Methods, strings.TrimPrefix(k, "http_method:"))
		case strings.HasPrefix(k, "http_path:"):
			d.Paths = append(d.Paths, strings.TrimPrefix(k, "http_path:"))
		case strings.HasPrefix(k, "tls_sni:"):
			d.SNIs = append(d.SNIs, strings.TrimPrefix(k, "tls_sni:"))
		case strings.HasPrefix(k, "src:"):
			d.SampleSources = append(d.SampleSources, strings.TrimPrefix(k, "src:"))
		default:
			switch k {
			case "http_requests":
				d.Requests = v
			case "tls_handshakes":
				d.Handshakes = v
			case "tls_missing_sni":
				d.MissingSNI = v
			case "slowloris_connections":
				d.Connections = v
			case "unique_sources":
				d.UniqueSources = v
			case "window_seconds":
				d.WindowSeconds = int(v)
			case "alert_threshold":
				d.AlertThreshold = v
			}
		}
	}
	sort.Strings(d.Methods)
	sort.Strings(d.Paths)
	sort.Strings(d.SNIs)
	sort.Strings(d.SampleSources)
	return d
}

// Observe records a Node-reported L7 event. Nil/empty events are ignored.
func (s *Store) Observe(nodeID string, at time.Time, eventType, dstIP string, counters map[string]uint64) {
	if eventType == "" {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	kind := kindOf(eventType)
	ev := Event{
		NodeID:   nodeID,
		Type:     kind,
		DstIP:    dstIP,
		At:       at,
		Detail:   parseDetail(counters),
		Counters: counters,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.events) >= s.maxEvents {
		// Drop the oldest quarter at once; shifting one element per event on a
		// 5000-entry ring is wasteful under a flood.
		drop := s.maxEvents / 4
		if drop < 1 {
			drop = 1
		}
		s.events = append(s.events[:0], s.events[drop:]...)
		s.dropped += uint64(drop)
	}
	s.events = append(s.events, ev)

	if dstIP != "" {
		t, ok := s.targets[dstIP]
		if !ok {
			if len(s.targets) >= s.maxTargets {
				s.evictStalestTargetLocked()
			}
			t = &Target{DstIP: dstIP}
			s.targets[dstIP] = t
		}
		switch kind {
		case KindHTTPFlood:
			t.HTTP++
		case KindTLSAnomaly:
			t.TLS++
		case KindSlowloris:
			t.Slowloris++
		}
		t.Total++
		if at.After(t.LastAt) {
			t.LastAt = at
		}
	}
	for _, src := range ev.Detail.SampleSources {
		if src != "" {
			s.sources[src]++
		}
	}
	if nodeID != "" {
		s.nodes[nodeID]++
	}
	for k, v := range counters {
		switch {
		case strings.HasPrefix(k, "tls_ja3:"):
			s.ja3[strings.TrimPrefix(k, "tls_ja3:")] += v
		case strings.HasPrefix(k, "tls_ja4:"):
			s.ja4[strings.TrimPrefix(k, "tls_ja4:")] += v
		case strings.HasPrefix(k, "http_ua:"):
			s.uas[strings.TrimPrefix(k, "http_ua:")] += v
		}
	}
	s.appendSeriesLocked(at, kind)
}

func (s *Store) evictStalestTargetLocked() {
	var oldestKey string
	var oldest time.Time
	for k, v := range s.targets {
		if oldestKey == "" || v.LastAt.Before(oldest) {
			oldestKey, oldest = k, v.LastAt
		}
	}
	if oldestKey != "" {
		delete(s.targets, oldestKey)
	}
}

func (s *Store) appendSeriesLocked(at time.Time, kind string) {
	slot := at.Truncate(s.bucketWidth)
	if n := len(s.series); n > 0 {
		if last := s.series[n-1]; last.at.Equal(slot) {
			s.bumpBucketLocked(&s.series[n-1], kind)
			return
		}
	}
	s.series = append(s.series, bucket{at: slot})
	s.bumpBucketLocked(&s.series[len(s.series)-1], kind)

	cutoff := slot.Add(-s.seriesSpan)
	keep := 0
	for keep < len(s.series) && s.series[keep].at.Before(cutoff) {
		keep++
	}
	if keep > 0 {
		s.series = append(s.series[:0], s.series[keep:]...)
	}
	if len(s.series) > s.maxSeries {
		s.series = append(s.series[:0], s.series[len(s.series)-s.maxSeries:]...)
	}
}

func (s *Store) bumpBucketLocked(b *bucket, kind string) {
	switch kind {
	case KindHTTPFlood:
		b.http++
	case KindTLSAnomaly:
		b.tls++
	case KindSlowloris:
		b.slowloris++
	}
}

// Snapshot returns an aggregated view of the last `window`.
func (s *Store) Snapshot(window time.Duration, now time.Time) Snapshot {
	if window <= 0 {
		window = 15 * time.Minute
	}
	if now.IsZero() {
		now = time.Now()
	}
	cutoff := now.Add(-window)

	s.mu.Lock()
	defer s.mu.Unlock()

	snap := Snapshot{
		GeneratedAt:   now,
		WindowMinutes: int(window.Minutes()),
		BucketSeconds: int(s.bucketWidth.Seconds()),
		Totals:        map[string]uint64{},
		Rates:         map[string]float64{},
		Dropped:       s.dropped,
	}

	seconds := window.Seconds()
	if seconds <= 0 {
		seconds = 1
	}

	for _, ev := range s.events {
		if ev.At.Before(cutoff) {
			continue
		}
		snap.Totals[ev.Type]++
		if len(snap.Recent) < 100 {
			snap.Recent = append(snap.Recent, ev)
		}
	}
	// Newest first: the console renders this list top-down.
	for i, j := 0, len(snap.Recent)-1; i < j; i, j = i+1, j-1 {
		snap.Recent[i], snap.Recent[j] = snap.Recent[j], snap.Recent[i]
	}
	for k, v := range snap.Totals {
		snap.Rates[k] = float64(v) / seconds
	}

	buckets := s.series
	if len(buckets) > 0 {
		start := 0
		for start < len(buckets) && buckets[start].at.Before(cutoff) {
			start++
		}
		for _, b := range buckets[start:] {
			snap.Series = append(snap.Series, Point{At: b.at, HTTP: b.http, TLS: b.tls, Slowloris: b.slowloris})
		}
	}

	for _, t := range s.targets {
		if t.LastAt.Before(cutoff) {
			continue
		}
		snap.Targets = append(snap.Targets, *t)
	}
	sort.Slice(snap.Targets, func(i, j int) bool {
		if snap.Targets[i].Total != snap.Targets[j].Total {
			return snap.Targets[i].Total > snap.Targets[j].Total
		}
		return snap.Targets[i].DstIP < snap.Targets[j].DstIP
	})
	if len(snap.Targets) > 25 {
		snap.Targets = snap.Targets[:25]
	}

	snap.Sources = topCounters(s.sources, 25)
	snap.Nodes = topCounters(s.nodes, 25)
	snap.JA3 = topCounters(s.ja3, 15)
	snap.JA4 = topCounters(s.ja4, 15)
	snap.UserAgents = topCounters(s.uas, 15)
	return snap
}

// Recent returns up to limit stored events, newest first.
func (s *Store) Recent(limit int) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > len(s.events) {
		limit = len(s.events)
	}
	out := make([]Event, 0, limit)
	for i := len(s.events) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.events[i])
	}
	return out
}

// Stats reports the store's internal counters for the health endpoint.
func (s *Store) Stats() (events int, dropped uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events), s.dropped
}

func topCounters(m map[string]uint64, n int) []Counter {
	out := make([]Counter, 0, len(m))
	for k, v := range m {
		out = append(out, Counter{Label: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Label < out[j].Label
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
