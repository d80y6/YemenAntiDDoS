package threshold

import (
	"bytes"
	"context"
	"log"
	"net"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestDao14b2_C6(t *testing.T) {
	for _, name := range []string{"DisabledParentInherits", "DisabledParentOverrideInherits", "DisabledMiddle", "CycleThroughDisabled", "NonInheritableStaysOnDisabled", "DisabledNotWatched", "DisabledBadCIDRSilent"} {
		t.Run(name, func(t *testing.T) {
			pa, pb := dao13aPrefix(1, nil), dao13aPrefix(2, dao13aInt(1))
			pa.Enabled = false
			pa.ThresholdTemplateID = dao13aInt(5)
			rule := store.Threshold{ID: 30, TemplateID: dao13aInt(5), Domain: "internal_ip", Direction: "receives", Decoder: "udp", Unit: "pps", Comparison: "over", Value: 300, Inheritable: true, Enabled: true}
			s := dao13aTreeStore{prefixes: []store.WatchPrefix{pa, pb}, rules: []store.Threshold{rule}}
			target := pb
			wantPrefixes := []string{pb.Prefix}
			wantRule := true
			switch name {
			case "DisabledParentOverrideInherits":
				s.prefixes[0].ThresholdTemplateID = nil
				s.rules[0].TemplateID = nil
				s.rules[0].PrefixID = dao13aInt(1)
			case "DisabledMiddle":
				s.prefixes[0].Enabled = true
				s.prefixes[1].Enabled = false
				target = dao13aPrefix(3, dao13aInt(2))
				s.prefixes = append(s.prefixes, target)
				wantPrefixes = []string{pa.Prefix, target.Prefix}
			case "CycleThroughDisabled":
				s.prefixes[0].Enabled = true
				s.prefixes[0].ParentID = dao13aInt(2)
				s.prefixes[0].ThresholdTemplateID = nil
				s.prefixes[1].Enabled = false
				s.prefixes[1].ThresholdTemplateID = dao13aInt(5)
				target = s.prefixes[0]
				wantPrefixes = []string{target.Prefix}
			case "NonInheritableStaysOnDisabled":
				s.rules[0].Inheritable = false
				wantRule = false
			case "DisabledNotWatched":
				s.prefixes[0].Prefix = "0.0.0.0/0"
				wantRule = false
			case "DisabledBadCIDRSilent":
				s.prefixes[0].Prefix = "not-a-cidr"
				bad := dao13aPrefix(3, nil)
				bad.Prefix = "also-not-a-cidr"
				s.prefixes = append(s.prefixes, bad)
				wantRule = false
			}
			var logs bytes.Buffer
			old := log.Writer()
			log.SetOutput(&logs)
			defer log.SetOutput(old)
			tree := NewTree()
			if err := tree.Rebuild(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			if wantRule {
				want := engine.ResolvedThreshold{ThresholdID: 30, PrefixID: target.ID, Prefix: target.Prefix, Domain: "internal_ip", Direction: "receives", Decoder: "udp", Unit: "pps", Comparison: "over", Value: 300}
				dao13aResolvedEqual(t, tree.ForPrefix(target.Prefix), []engine.ResolvedThreshold{want})
			} else if name != "DisabledNotWatched" && len(tree.ForPrefix(target.Prefix)) != 0 {
				t.Errorf("unexpected inherited rules: %+v", tree.ForPrefix(target.Prefix))
			}
			for _, p := range s.prefixes {
				if !p.Enabled && len(tree.ForPrefix(p.Prefix)) != 0 {
					t.Errorf("disabled prefix %s produced rules", p.Prefix)
				}
			}
			got := append([]string(nil), tree.AllPrefixes()...)
			sort.Strings(got)
			sort.Strings(wantPrefixes)
			if !reflect.DeepEqual(got, wantPrefixes) {
				t.Errorf("watched=%v; want %v", got, wantPrefixes)
			}
			if name == "CycleThroughDisabled" {
				if strings.Count(logs.String(), "ERROR") != 1 || !strings.Contains(logs.String(), "prefix_id=1 chain=[1 2]") {
					t.Errorf("cycle logs=%q", logs.String())
				}
			}
			if name == "DisabledNotWatched" {
				if tree.HasGlobalPrefix() || tree.FindPrefixForIP(net.ParseIP("203.0.113.1")) != "" {
					t.Error("disabled global prefix was watched")
				}
			}
			if name == "DisabledBadCIDRSilent" {
				if strings.Count(logs.String(), "skip bad prefix") != 1 || strings.Contains(logs.String(), `skip bad prefix "not-a-cidr"`) || !strings.Contains(logs.String(), `skip bad prefix "also-not-a-cidr"`) {
					t.Errorf("bad prefix logs=%q", logs.String())
				}
			}
		})
	}
}
