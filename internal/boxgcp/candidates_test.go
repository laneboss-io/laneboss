package boxgcp

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

// TestCandidates rejects wrong price ties, filters, explicit overrides and capacity kinds.
func TestCandidates(t *testing.T) {
	cfg := testConfig()
	cfg.Shapes = []boxcore.GCPShape{
		{Type: "demo-large", VCPU: 2, MemGiB: 8, Arch: "x86", PriceUSDHour: 0.07},
		{Type: "demo-tie", VCPU: 2, MemGiB: 4, PriceUSDHour: 0.02},
		{Type: "demo-arm", VCPU: 2, MemGiB: 6, Arch: "arm64", PriceUSDHour: 0.02},
		{Type: "demo-tiny", VCPU: 2, MemGiB: 2, Arch: "x86", PriceUSDHour: 0.01},
		{Type: "demox-near", VCPU: 2, MemGiB: 4, Arch: "x86", PriceUSDHour: 0.03},
		{Type: "demo-many", VCPU: 4, MemGiB: 16, Arch: "x86", PriceUSDHour: 0.005},
	}
	wantRows := func(indexes []int, zones []string) []boxcore.Candidate {
		var want []boxcore.Candidate
		for _, index := range indexes {
			shape := cfg.Shapes[index]
			arch := "x86"
			if index == 2 {
				arch = "arm64"
			}
			for _, zone := range zones {
				want = append(want, boxcore.Candidate{Type: shape.Type, Zone: zone, Region: cfg.Region,
					Arch: arch, PriceUSDHour: shape.PriceUSDHour})
			}
		}
		return want
	}
	cases := []struct {
		name, arch string
		mem, vcpu  int
		families   []string
		rows       []int
	}{
		{"price-ties", "any", 4, 2, nil, []int{1, 2, 4, 0}},
		{"x86", "x86", 4, 2, nil, []int{1, 4, 0}},
		{"empty-arch", "", 4, 2, nil, []int{1, 4, 0}},
		{"arm", "arm64", 4, 2, nil, []int{2}},
		{"memory", "any", 7, 2, nil, []int{0}},
		{"no-minimum", "any", -1, 2, nil, []int{3, 1, 2, 4, 0}},
		{"family", "any", 4, 2, []string{"demo"}, []int{1, 2, 0}},
		{"family-union", "any", 4, 2, []string{"demo", "demox"}, []int{1, 2, 4, 0}},
		{"family-boundary", "any", 4, 2, []string{"dem"}, nil},
		{"vcpu", "any", 4, 4, nil, []int{5}},
		{"capacity", "any", 4, 9, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &boxexec.Fake{}
			req := boxcore.Request{VCPU: tc.vcpu, MemGiB: tc.mem, Arch: tc.arch, Families: tc.families}
			got, err := New(cfg, f, testOptions()).Candidates(context.Background(), req)
			if len(tc.rows) == 0 {
				requireKind(t, err, boxcore.KindCapacity)
				if got != nil || strings.Contains(err.Error(), "demo") ||
					!strings.Contains(err.Error(), "vCPU") {
					t.Fatal("capacity error leaked filter values or omitted vCPU")
				}
			} else if err != nil || !reflect.DeepEqual(got, wantRows(tc.rows, cfg.Zones)) {
				t.Fatalf("wrong candidate order or fields: %v", err)
			}
			if len(f.Calls) != 0 {
				t.Fatal("candidate selection ran a child")
			}
		})
	}
	for _, tc := range []struct {
		name, typ, zone, arch string
		price                 float64
		wantErr               bool
	}{
		{"explicit-known", "demo-arm", "demo-zone-b", "arm64", 0.02, false},
		{"explicit-unknown", "demo-custom", "demo-zone-a", "x86", 0, false},
		{"unknown-zone", "demo-arm", "demo-zone-other", "arm64", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := boxcore.Request{Type: tc.typ, Zone: tc.zone, Arch: "any", VCPU: 99, MemGiB: 99, Families: []string{"other"}}
			got, err := New(cfg, &boxexec.Fake{}, testOptions()).Candidates(context.Background(), req)
			if tc.wantErr {
				if err == nil || strings.Contains(err.Error(), tc.zone) {
					t.Fatal("unknown explicit zone was accepted or exposed")
				}
				return
			}
			want := []boxcore.Candidate{{Type: tc.typ, Zone: tc.zone, Region: cfg.Region, Arch: tc.arch, PriceUSDHour: tc.price}}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("explicit pair did not bypass filters: %v", err)
			}
		})
	}
	t.Run("partial-zone", func(t *testing.T) {
		got, err := New(cfg, &boxexec.Fake{}, testOptions()).Candidates(context.Background(),
			boxcore.Request{VCPU: 2, MemGiB: 4, Arch: "any", Zone: cfg.Zones[1]})
		if err != nil || !reflect.DeepEqual(got, wantRows([]int{1, 2, 4, 0}, cfg.Zones[1:])) {
			t.Fatal("partial zone filter was ignored")
		}
	})
}
