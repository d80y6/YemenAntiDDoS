package postgres

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func TestFlowLogWhere_C16(t *testing.T) {
	from := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Minute)
	for _, column := range []string{"dst_ip", "src_ip"} {
		for _, tc := range []struct {
			name       string
			filter     store.FlowLogFilter
			conditions []string
			args       []any
			limit      int
		}{
			{"udp", store.FlowLogFilter{DstIP: "198.51.100.7", Protocols: []int{17}, Limit: 37}, []string{column + " = $1::INET", "protocol = ANY($2)"}, []any{"198.51.100.7", []int{17}}, 37},
			{"tcp_syn", store.FlowLogFilter{Protocols: []int{6}, TCPFlagsAll: 2, TCPFlagsNone: 16}, []string{"protocol = ANY($1)", "tcp_flags & $2 = $2", "tcp_flags & $3 = 0"}, []any{[]int{6}, 2, 16}, 1000},
			{"fragment", store.FlowLogFilter{DstIP: "198.51.100.0/24"}, []string{column + " <<= $1::CIDR"}, []any{"198.51.100.0/24"}, 1000},
			{"all_fields", store.FlowLogFilter{DstIP: "198.51.100.7", From: from, To: to, Protocols: []int{6, 17}, TCPFlagsAll: 2, TCPFlagsNone: 16, Limit: 99999}, []string{column + " = $1::INET", "time >= $2", "time <= $3", "protocol = ANY($4)", "tcp_flags & $5 = $5", "tcp_flags & $6 = 0"}, []any{"198.51.100.7", from, to, []int{6, 17}, 2, 16}, 10000},
			{"time_only", store.FlowLogFilter{From: from, To: to}, []string{"time >= $1", "time <= $2"}, []any{from, to}, 1000},
			{"to_and_none", store.FlowLogFilter{To: to, TCPFlagsNone: 2}, []string{"time <= $1", "tcp_flags & $2 = 0"}, []any{to, 2}, 1000},
			{"all_only", store.FlowLogFilter{TCPFlagsAll: 4}, []string{"tcp_flags & $1 = $1"}, []any{4}, 1000},
			{"empty", store.FlowLogFilter{}, nil, nil, 1000},
		} {
			t.Run(column+"/"+tc.name, func(t *testing.T) {
				where, args := flowLogWhere(tc.filter, column)
				want := ""
				if len(tc.conditions) > 0 {
					want = " WHERE " + strings.Join(tc.conditions, " AND ")
				}
				if where != want || !reflect.DeepEqual(args, tc.args) {
					t.Fatalf("WHERE=%q args=%#v want=%q %#v", where, args, want, tc.args)
				}
				query, queryArgs := flowLogQuery(tc.filter, column)
				if !reflect.DeepEqual(queryArgs, tc.args) {
					t.Fatalf("final args=%#v want=%#v", queryArgs, tc.args)
				}
				order := strings.Index(query, "ORDER BY packets DESC")
				if order < 0 {
					t.Fatal(query)
				}
				for _, condition := range tc.conditions {
					index := strings.Index(query, condition)
					if index < 0 || index >= order {
						t.Errorf("condition %q is absent or after ORDER BY: %s", condition, query)
					}
				}
				if !strings.HasSuffix(strings.TrimSpace(query), fmt.Sprintf("LIMIT %d", tc.limit)) {
					t.Fatal(query)
				}
				seen := map[int]bool{}
				for _, match := range regexp.MustCompile(`\$(\d+)`).FindAllStringSubmatch(query, -1) {
					n, _ := strconv.Atoi(match[1])
					seen[n] = true
					if n < 1 || n > len(queryArgs) {
						t.Errorf("placeholder $%d has no argument", n)
					}
				}
				if len(seen) != len(queryArgs) {
					t.Fatalf("placeholders=%v args=%#v", seen, queryArgs)
				}
				for n := 1; n <= len(queryArgs); n++ {
					if !seen[n] {
						t.Errorf("missing $%d", n)
					}
				}
				if tc.name == "fragment" && (strings.Contains(where, "protocol") || strings.Contains(where, "tcp_flags")) {
					t.Fatal(where)
				}
			})
		}
	}
}
