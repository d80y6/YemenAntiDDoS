// Package ring implements in-memory ring buffers for real-time traffic data.
//
// Architecture:
//   - RingStore holds two directionStore instances (inbound + outbound)
//   - Each directionStore has per-prefix and per-IP ring buffers
//   - Each ring is a fixed-capacity circular buffer of DataPoints (1 per second)
//   - At capacity, stale unprotected keys go first; otherwise only heavier newcomers displace the lightest key
//   - Active and confirming attacks protect IP keys, subject to the all-protected global fallback
//   - Consecutive arrivals with the same timestamp overwrite the latest slot
//
// v2.11 Phase 2: refactored to directionStore to share all logic between
// inbound (dst_ip) and outbound (src_ip) without code duplication.
package ring

import (
	"net"
	"sync"
	"time"

	"github.com/d80y6/YemenDDoS/shared/decoder"
)

// StaleAfter must equal threshold.ringFreshnessWindow.
const StaleAfter = 5 * time.Second

// DataPoint holds one second of aggregated traffic statistics.
type DataPoint struct {
	Time       time.Time
	PPS        int64
	BPS        int64
	DecoderPPS [decoder.MaxDecoders]int32
	DecoderBPS [decoder.MaxDecoders]int64
	ActiveIPs  uint32
	Overflow   uint32
}

// Limits configures hard upper bounds for the ring store.
type Limits struct {
	MaxIPsPerPrefix int // default 10,000
	MaxPointsPerIP  int // default 120
	MaxGlobalKeys   int // default 100,000
}

// DefaultLimits is a test fixture; production uses config.Ring (defaults in config/config.go).
func DefaultLimits() Limits {
	return Limits{
		MaxIPsPerPrefix: 10_000,
		MaxPointsPerIP:  120,
		MaxGlobalKeys:   100_000,
	}
}

// ---------------------------------------------------------------------------
// directionStore — the single implementation for one traffic direction.
// Both inbound and outbound use the same struct with identical LRU,
// eviction, MarkActive, and limit enforcement logic.
// ---------------------------------------------------------------------------

type directionStore struct {
	prefixes  map[string]*PrefixRing
	ips       map[string]*IPRing
	ipAccess  map[string]time.Time
	activeIPs map[string]bool
}

func newDirectionStore() *directionStore {
	return &directionStore{
		prefixes:  make(map[string]*PrefixRing),
		ips:       make(map[string]*IPRing),
		ipAccess:  make(map[string]time.Time),
		activeIPs: make(map[string]bool),
	}
}

func (d *directionStore) pushPrefix(key, prefix string, capacity int, dp DataPoint) {
	pr, ok := d.prefixes[key]
	if !ok {
		pr = newPrefixRing(prefix, capacity)
		d.prefixes[key] = pr
	}
	pr.put(dp)
}

func (d *directionStore) pushIP(pKey, iKey, ipStr, prefix string, limits Limits, dp DataPoint) {
	ir, ok := d.ips[iKey]
	if !ok {
		pr := d.prefixes[pKey]
		if pr != nil && len(pr.ipKeys) >= limits.MaxIPsPerPrefix {
			if !d.admitNewcomer(pr.ipKeys, dp.PPS, false) {
				return
			}
		}
		if len(d.ips) >= limits.MaxGlobalKeys {
			if !d.admitNewcomer(nil, dp.PPS, true) {
				return
			}
		}
		ir = newIPRing(ipStr, prefix, limits.MaxPointsPerIP)
		d.ips[iKey] = ir
		if pr == nil {
			pr = newPrefixRing(prefix, limits.MaxPointsPerIP)
			d.prefixes[pKey] = pr
		}
		pr.ipKeys[iKey] = struct{}{}
	}
	ir.put(dp)
	d.ipAccess[iKey] = dp.Time
}

func (d *directionStore) getPrefixRing(key string) *PrefixRing {
	return d.prefixes[key]
}

func (d *directionStore) getIPRing(key string) *IPRing {
	return d.ips[key]
}

func (d *directionStore) ipKeysForPrefix(pKey string) []string {
	pr := d.prefixes[pKey]
	if pr == nil {
		return nil
	}
	pfx := pKey + ":"
	result := make([]string, 0, len(pr.ipKeys))
	for key := range pr.ipKeys {
		if len(key) > len(pfx) {
			result = append(result, key[len(pfx):])
		}
	}
	return result
}

func (d *directionStore) markActive(key string)  { d.activeIPs[key] = true }
func (d *directionStore) clearActive(key string) { delete(d.activeIPs, key) }

func (d *directionStore) stats() (prefixCount, ipCount, activeCount int) {
	return len(d.prefixes), len(d.ips), len(d.activeIPs)
}

// evictOne removes the LRU non-attack IP ring.
func (d *directionStore) evictOne() {
	var oldest string
	var oldestTime time.Time
	for key, t := range d.ipAccess {
		if d.activeIPs[key] {
			continue
		}
		if oldest == "" || t.Before(oldestTime) {
			oldest = key
			oldestTime = t
		}
	}
	if oldest == "" {
		for key, t := range d.ipAccess {
			if oldest == "" || t.Before(oldestTime) {
				oldest = key
				oldestTime = t
			}
		}
	}
	if oldest != "" {
		d.removeIP(oldest)
	}
}

// admitNewcomer first removes the oldest stale unprotected key in scope.
// Otherwise it admits only a strictly heavier newcomer than the lightest key.
// A nil scope selects all keys. If every key is protected, preserve the global
// LRU fallback or the per-prefix soft overflow. The caller holds the store lock.
func (d *directionStore) admitNewcomer(scope map[string]struct{}, newPPS int64, global bool) bool {
	var stale, light string
	var staleTime time.Time
	var lightPPS int64
	unprotected := 0
	inspect := func(key string) {
		if d.activeIPs[key] {
			return
		}
		unprotected++
		at := d.ipAccess[key]
		if time.Since(at) > StaleAfter {
			if stale == "" || at.Before(staleTime) {
				stale, staleTime = key, at
			}
			return
		}
		var pps int64
		ir := d.ips[key]
		if ir.count > 0 {
			pps = ir.buf[(ir.head-1+ir.cap)%ir.cap].PPS
		}
		if light == "" || pps < lightPPS {
			light, lightPPS = key, pps
		}
	}
	if scope != nil {
		for key := range scope {
			inspect(key)
		}
	} else {
		for key := range d.ips {
			inspect(key)
		}
	}
	switch {
	case stale != "":
		d.removeIP(stale)
		return true
	case light != "" && lightPPS < newPPS:
		d.removeIP(light)
		return true
	case unprotected > 0:
		return false
	}
	if global {
		d.evictOne()
	}
	return true
}

// removeIP deletes an IP ring and all its tracking data.
func (d *directionStore) removeIP(key string) {
	ir, ok := d.ips[key]
	if !ok {
		return
	}
	delete(d.ips, key)
	delete(d.ipAccess, key)
	delete(d.activeIPs, key)
	pKey := key[:len(key)-len(":")-len(ir.DstIP)]
	pr := d.prefixes[pKey]
	if pr != nil {
		delete(pr.ipKeys, key)
	}
}

// ---------------------------------------------------------------------------
// PrefixRing / IPRing — unchanged circular buffer types
// ---------------------------------------------------------------------------

type PrefixRing struct {
	Prefix string
	buf    []DataPoint
	head   int
	count  int
	cap    int
	ipKeys map[string]struct{}
}

func newPrefixRing(prefix string, capacity int) *PrefixRing {
	return &PrefixRing{
		Prefix: prefix,
		buf:    make([]DataPoint, capacity),
		cap:    capacity,
		ipKeys: make(map[string]struct{}),
	}
}

func (r *PrefixRing) Push(dp DataPoint) {
	r.buf[r.head] = dp
	r.head = (r.head + 1) % r.cap
	if r.count < r.cap {
		r.count++
	}
}

// put keeps the last arrival when its timestamp matches the latest slot.
// A timestamp matching an older slot still appends in arrival order.
func (r *PrefixRing) put(dp DataPoint) {
	if r.count > 0 {
		idx := (r.head - 1 + r.cap) % r.cap
		if r.buf[idx].Time.Equal(dp.Time) {
			r.buf[idx] = dp
			return
		}
	}
	r.Push(dp)
}

func (r *PrefixRing) Latest(n int) []DataPoint {
	if n > r.count {
		n = r.count
	}
	result := make([]DataPoint, n)
	for i := 0; i < n; i++ {
		idx := (r.head - 1 - i + r.cap) % r.cap
		result[i] = r.buf[idx]
	}
	return result
}

func (r *PrefixRing) Count() int { return r.count }

func (r *PrefixRing) LatestOne(maxAge time.Duration) (DataPoint, bool) {
	if r.count == 0 {
		return DataPoint{}, false
	}
	idx := (r.head - 1 + r.cap) % r.cap
	dp := r.buf[idx]
	if maxAge > 0 && time.Since(dp.Time) > maxAge {
		return DataPoint{}, false
	}
	return dp, true
}

type IPRing struct {
	DstIP  string
	Prefix string
	buf    []DataPoint
	head   int
	count  int
	cap    int
}

func newIPRing(dstIP, prefix string, capacity int) *IPRing {
	return &IPRing{
		DstIP:  dstIP,
		Prefix: prefix,
		buf:    make([]DataPoint, capacity),
		cap:    capacity,
	}
}

func (r *IPRing) Push(dp DataPoint) {
	r.buf[r.head] = dp
	r.head = (r.head + 1) % r.cap
	if r.count < r.cap {
		r.count++
	}
}

// put keeps the last arrival when its timestamp matches the latest slot.
// A timestamp matching an older slot still appends in arrival order.
func (r *IPRing) put(dp DataPoint) {
	if r.count > 0 {
		idx := (r.head - 1 + r.cap) % r.cap
		if r.buf[idx].Time.Equal(dp.Time) {
			r.buf[idx] = dp
			return
		}
	}
	r.Push(dp)
}

func (r *IPRing) Latest(n int) []DataPoint {
	if n > r.count {
		n = r.count
	}
	result := make([]DataPoint, n)
	for i := 0; i < n; i++ {
		idx := (r.head - 1 - i + r.cap) % r.cap
		result[i] = r.buf[idx]
	}
	return result
}

func (r *IPRing) Count() int { return r.count }

func (r *IPRing) LatestOne(maxAge time.Duration) (DataPoint, bool) {
	if r.count == 0 {
		return DataPoint{}, false
	}
	idx := (r.head - 1 + r.cap) % r.cap
	dp := r.buf[idx]
	if maxAge > 0 && time.Since(dp.Time) > maxAge {
		return DataPoint{}, false
	}
	return dp, true
}

// ---------------------------------------------------------------------------
// RingStore — top-level container, delegates to directionStore
// ---------------------------------------------------------------------------

type NodePrefix struct {
	NodeID string
	Prefix string
}

func prefixKey(nodeID, prefix string) string { return nodeID + ":" + prefix }
func ipKey(nodeID, prefix, ip string) string { return nodeID + ":" + prefix + ":" + ip }

type RingStore struct {
	mu       sync.RWMutex
	inbound  *directionStore
	outbound *directionStore
	limits   Limits
}

func New(limits Limits) *RingStore {
	return &RingStore{
		inbound:  newDirectionStore(),
		outbound: newDirectionStore(),
		limits:   limits,
	}
}

// --- Inbound (dst_ip) public API ---

func (s *RingStore) PushPrefix(nodeID, prefix string, dp DataPoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inbound.pushPrefix(prefixKey(nodeID, prefix), prefix, s.limits.MaxPointsPerIP, dp)
}

func (s *RingStore) PushIP(nodeID, prefix string, dstIP net.IP, dp DataPoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inbound.pushIP(prefixKey(nodeID, prefix), ipKey(nodeID, prefix, dstIP.String()), dstIP.String(), prefix, s.limits, dp)
}

// The returned ring is not safe to read concurrently with Push; production readers use the Latest* methods.
func (s *RingStore) GetPrefixRing(nodeID, prefix string) *PrefixRing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inbound.getPrefixRing(prefixKey(nodeID, prefix))
}

// LatestPrefix returns the newest inbound prefix data point no older than maxAge.
// The ring is read under the store lock, so the point is never torn by a concurrent Push.
func (s *RingStore) LatestPrefix(nodeID, prefix string, maxAge time.Duration) (DataPoint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pr := s.inbound.getPrefixRing(prefixKey(nodeID, prefix))
	if pr == nil {
		return DataPoint{}, false
	}
	return pr.LatestOne(maxAge)
}

// The returned ring is not safe to read concurrently with Push; production readers use the Latest* methods.
func (s *RingStore) GetIPRing(nodeID, prefix string, dstIP net.IP) *IPRing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inbound.getIPRing(ipKey(nodeID, prefix, dstIP.String()))
}

// The returned ring is not safe to read concurrently with Push; production readers use the Latest* methods.
func (s *RingStore) GetIPRingByKey(nodeID, prefix, ipStr string) *IPRing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inbound.getIPRing(ipKey(nodeID, prefix, ipStr))
}

// LatestIPByKey returns the newest inbound ip data point no older than maxAge.
// The ring is read under the store lock, so the point is never torn by a concurrent Push.
func (s *RingStore) LatestIPByKey(nodeID, prefix, ipStr string, maxAge time.Duration) (DataPoint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ir := s.inbound.getIPRing(ipKey(nodeID, prefix, ipStr))
	if ir == nil {
		return DataPoint{}, false
	}
	return ir.LatestOne(maxAge)
}

func (s *RingStore) MarkActive(nodeID, prefix string, dstIP net.IP) {
	s.mu.Lock()
	s.inbound.markActive(ipKey(nodeID, prefix, dstIP.String()))
	s.mu.Unlock()
}

func (s *RingStore) ClearActive(nodeID, prefix string, dstIP net.IP) {
	s.mu.Lock()
	s.inbound.clearActive(ipKey(nodeID, prefix, dstIP.String()))
	s.mu.Unlock()
}

func (s *RingStore) IPKeysForPrefix(nodeID, prefix string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inbound.ipKeysForPrefix(prefixKey(nodeID, prefix))
}

// --- Outbound (src_ip) public API — same directionStore, different instance ---

func (s *RingStore) PushSrcPrefix(nodeID, prefix string, dp DataPoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outbound.pushPrefix(prefixKey(nodeID, prefix), prefix, s.limits.MaxPointsPerIP, dp)
}

func (s *RingStore) PushSrcIP(nodeID, prefix string, srcIP net.IP, dp DataPoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outbound.pushIP(prefixKey(nodeID, prefix), ipKey(nodeID, prefix, srcIP.String()), srcIP.String(), prefix, s.limits, dp)
}

// The returned ring is not safe to read concurrently with Push; production readers use the Latest* methods.
func (s *RingStore) GetSrcPrefixRing(nodeID, prefix string) *PrefixRing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.outbound.getPrefixRing(prefixKey(nodeID, prefix))
}

// LatestSrcPrefix returns the newest outbound prefix data point no older than maxAge.
// The ring is read under the store lock, so the point is never torn by a concurrent Push.
func (s *RingStore) LatestSrcPrefix(nodeID, prefix string, maxAge time.Duration) (DataPoint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pr := s.outbound.getPrefixRing(prefixKey(nodeID, prefix))
	if pr == nil {
		return DataPoint{}, false
	}
	return pr.LatestOne(maxAge)
}

// The returned ring is not safe to read concurrently with Push; production readers use the Latest* methods.
func (s *RingStore) GetSrcIPRingByKey(nodeID, prefix, ipStr string) *IPRing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.outbound.getIPRing(ipKey(nodeID, prefix, ipStr))
}

// LatestSrcIPByKey returns the newest outbound ip data point no older than maxAge.
// The ring is read under the store lock, so the point is never torn by a concurrent Push.
func (s *RingStore) LatestSrcIPByKey(nodeID, prefix, ipStr string, maxAge time.Duration) (DataPoint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ir := s.outbound.getIPRing(ipKey(nodeID, prefix, ipStr))
	if ir == nil {
		return DataPoint{}, false
	}
	return ir.LatestOne(maxAge)
}

func (s *RingStore) SrcIPKeysForPrefix(nodeID, prefix string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.outbound.ipKeysForPrefix(prefixKey(nodeID, prefix))
}

func (s *RingStore) MarkSrcActive(nodeID, prefix string, srcIP net.IP) {
	s.mu.Lock()
	s.outbound.markActive(ipKey(nodeID, prefix, srcIP.String()))
	s.mu.Unlock()
}

func (s *RingStore) ClearSrcActive(nodeID, prefix string, srcIP net.IP) {
	s.mu.Lock()
	s.outbound.clearActive(ipKey(nodeID, prefix, srcIP.String()))
	s.mu.Unlock()
}

// --- Shared ---

func (s *RingStore) AllNodePrefixes() []NodePrefix {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]NodePrefix, 0, len(s.inbound.prefixes))
	for key, pr := range s.inbound.prefixes {
		for i := 0; i < len(key); i++ {
			if key[i] == ':' {
				result = append(result, NodePrefix{NodeID: key[:i], Prefix: pr.Prefix})
				break
			}
		}
	}
	return result
}

func (s *RingStore) AllOutboundNodePrefixes() []NodePrefix {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]NodePrefix, 0, len(s.outbound.prefixes))
	for key, pr := range s.outbound.prefixes {
		for i := 0; i < len(key); i++ {
			if key[i] == ':' {
				result = append(result, NodePrefix{NodeID: key[:i], Prefix: pr.Prefix})
				break
			}
		}
	}
	return result
}

func (s *RingStore) Stats() (prefixCount, ipCount, activeCount int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ip, iip, ia := s.inbound.stats()
	op, oip, oa := s.outbound.stats()
	return ip + op, iip + oip, ia + oa
}

// LatestNPrefix copies up to n points in newest-first arrival order under the store lock.
func (s *RingStore) LatestNPrefix(nodeID, prefix string, n int) []DataPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.inbound.getPrefixRing(prefixKey(nodeID, prefix))
	if r == nil || n < 1 {
		return nil
	}
	return r.Latest(n)
}

// LatestNSrcPrefix copies up to n points in newest-first arrival order under the store lock.
func (s *RingStore) LatestNSrcPrefix(nodeID, prefix string, n int) []DataPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.outbound.getPrefixRing(prefixKey(nodeID, prefix))
	if r == nil || n < 1 {
		return nil
	}
	return r.Latest(n)
}

// LatestNIPByKey copies up to n points in newest-first arrival order under the store lock.
func (s *RingStore) LatestNIPByKey(nodeID, prefix, ipStr string, n int) []DataPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.inbound.getIPRing(ipKey(nodeID, prefix, ipStr))
	if r == nil || n < 1 {
		return nil
	}
	return r.Latest(n)
}

// LatestNSrcIPByKey copies up to n points in newest-first arrival order under the store lock.
func (s *RingStore) LatestNSrcIPByKey(nodeID, prefix, ipStr string, n int) []DataPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.outbound.getIPRing(ipKey(nodeID, prefix, ipStr))
	if r == nil || n < 1 {
		return nil
	}
	return r.Latest(n)
}
