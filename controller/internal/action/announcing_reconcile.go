package action

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type announcingObservation struct {
	gen       int
	firstSeen time.Time
}

// RunAnnouncingReconcile repairs labels only after a full observation interval.
func (e *Engine) RunAnnouncingReconcile(ctx context.Context, interval time.Duration) {
	observed := make(map[int]announcingObservation)
	for {
		if ctx.Err() != nil {
			return
		}
		rows, err := e.store.BGPAnnouncements().ListByStatus(ctx, "announcing")
		if err != nil {
			metrics.BGPAnnouncingReconcile.WithLabelValues("list_error").Inc()
			log.Printf("action: announcing reconcile list: %v", err)
		} else {
			now := time.Now()
			next := make(map[int]announcingObservation, len(rows))
			for _, ann := range rows {
				seen, exists := observed[ann.ID]
				same := exists && seen.gen == ann.Gen
				if !same {
					seen = announcingObservation{gen: ann.Gen, firstSeen: now}
				}
				next[ann.ID] = seen
				if same && now.Sub(seen.firstSeen) >= interval {
					if e.reconcileAnnouncing(ctx, ann) {
						delete(next, ann.ID)
					}
				}
			}
			observed = next
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (e *Engine) reconcileAnnouncing(ctx context.Context, ann store.BGPAnnouncement) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := e.store.BGPConnectors().Get(ctx, ann.ConnectorID)
	if err != nil {
		metrics.BGPAnnouncingReconcile.WithLabelValues("lookup_error").Inc()
		return false
	}
	if !conn.Enabled || conn.VtyshPath == "" {
		metrics.BGPAnnouncingReconcile.WithLabelValues("skipped_disabled").Inc()
		return false
	}
	present, outcome, err := announcementInFRR(ctx, conn, ann)
	if err != nil {
		metrics.BGPAnnouncingReconcile.WithLabelValues("probe_error").Inc()
		log.Printf("ERROR action: announcing probe announcement_id=%d: %v", ann.ID, err)
		return false
	}
	if !present {
		metrics.BGPAnnouncingReconcile.WithLabelValues(outcome).Inc()
		log.Printf("ERROR action: announcing reconcile announcement_id=%d prefix=%s route-map=%s connector=%d outcome=%s; attached attacks rely on this route", ann.ID, ann.Prefix, ann.RouteMap, ann.ConnectorID, outcome)
		return false
	}
	err = retryBGPStateWrite(func(writeCtx context.Context) error {
		return e.store.BGPAnnouncements().MarkAnnounced(writeCtx, ann.ID, ann.Gen)
	})
	if err == nil {
		metrics.BGPAnnouncingReconcile.WithLabelValues("announced").Inc()
		log.Printf("action: announcing label repaired announcement_id=%d gen=%d", ann.ID, ann.Gen)
		return true
	}
	if bgpStateNotApplied(err, ann.ID, ann.Gen, "announced") {
		metrics.BGPAnnouncingReconcile.WithLabelValues("stale").Inc()
		return true
	}
	metrics.BGPAnnouncingReconcile.WithLabelValues("state_write_error").Inc()
	metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
	log.Printf("ERROR action: announcing state write announcement_id=%d: %v", ann.ID, err)
	return false
}

func announcementInFRR(ctx context.Context, conn *store.BGPConnector, ann store.BGPAnnouncement) (bool, string, error) {
	config, err := runVtysh(ctx, conn.VtyshPath, "show running-config")
	if err != nil {
		return false, "", err
	}
	rib, err := runVtysh(ctx, conn.VtyshPath, "show bgp "+addressFamilyForPrefix(ann.Prefix)+" json")
	if err != nil {
		return false, "", err
	}
	inRIB, err := announcingRIBContains(rib, ann.Prefix)
	if err != nil {
		return false, "", err
	}
	if !announcingConfigContains(config, conn.BGPASN, ann) {
		return false, "absent", nil
	}
	if !inRIB {
		return false, "config_only", nil
	}
	return true, "", nil
}

func announcingPrefix(prefix string) string {
	_, network, err := net.ParseCIDR(prefix)
	if err != nil {
		return ""
	}
	return network.String()
}

func announcingConfigContains(output string, asn int, ann store.BGPAnnouncement) bool {
	target := announcingPrefix(ann.Prefix)
	inBGP, family := false, ""
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "router bgp ") {
			inBGP, family = line == fmt.Sprintf("router bgp %d", asn), ""
			continue
		}
		if line != "" && raw == strings.TrimLeft(raw, " \t") {
			inBGP, family = false, ""
		}
		if !inBGP {
			continue
		}
		if strings.HasPrefix(line, "address-family ") {
			family = strings.TrimPrefix(line, "address-family ")
		} else if line == "exit-address-family" {
			family = ""
		}
		fields := strings.Fields(line)
		if target != "" && family == addressFamilyForPrefix(ann.Prefix) && len(fields) == 4 && fields[0] == "network" && fields[2] == "route-map" && fields[3] == ann.RouteMap && announcingPrefix(fields[1]) == target {
			return true
		}
	}
	return false
}

func announcingRIBContains(output, prefix string) (bool, error) {
	if err := announcingStrictKeys(output); err != nil {
		return false, err
	}
	var rib struct {
		Routes map[string][]struct {
			Weight                              *int
			Path, PeerID                        *string
			Nexthops                            []struct{ IP *string }
			History, Removed, Stale, RibFailure bool
		}
	}
	if err := json.Unmarshal([]byte(output), &rib); err != nil {
		return false, err
	}
	target, zero := announcingPrefix(prefix), "0.0.0.0"
	if addressFamilyForPrefix(prefix) == "ipv6 unicast" {
		zero = "::"
	}
	for key, paths := range rib.Routes {
		if target == "" || announcingPrefix(key) != target {
			continue
		}
		for _, path := range paths {
			if path.Weight == nil || *path.Weight != 32768 || path.Path == nil || *path.Path != "" || path.PeerID == nil || *path.PeerID != "(unspec)" || path.History || path.Removed || path.Stale || path.RibFailure {
				continue
			}
			local := len(path.Nexthops) > 0
			for _, hop := range path.Nexthops {
				if hop.IP == nil || *hop.IP != zero {
					local = false
				}
			}
			if local {
				return true, nil
			}
		}
	}
	return false, nil
}

func announcingStrictKeys(output string) error {
	decoder := json.NewDecoder(strings.NewReader(output))
	var value func() error
	value = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, container := token.(json.Delim)
		if !container {
			return nil
		}
		seen := make(map[string]bool)
		for decoder.More() {
			if delim == '{' {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				k := key.(string)
				for _, n := range []string{"routes", "weight", "path", "peerId", "nexthops", "ip", "history", "removed", "stale", "ribFailure"} {
					if strings.EqualFold(k, n) {
						if k != n || seen[n] {
							return fmt.Errorf("ambiguous BGP JSON key %q", k)
						}
						seen[n] = true
					}
				}
			}
			if err := value(); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	return value()
}
