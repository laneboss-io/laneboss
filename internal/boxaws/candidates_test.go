package boxaws

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

func priceRow(name, zone, price, timestamp string) map[string]string {
	return map[string]string{"InstanceType": name, "AvailabilityZone": zone,
		"SpotPrice": price, "Timestamp": timestamp}
}

func priceFake(t *testing.T, rows ...map[string]string) *boxexec.Fake {
	t.Helper()
	text := jsonText(t, map[string]any{"SpotPriceHistory": rows})
	return &boxexec.Fake{Handlers: []boxexec.Handler{reply("aws", "ec2 describe-spot-price-history", text)}}
}

func TestCandidateFilters(t *testing.T) {
	cases := []struct {
		name, arch string
		memory     int
		families   []string
		want       []string
	}{
		{"x86", "x86", 0, nil, []string{"c7i.xlarge", "m7i.xlarge", "q7i.xlarge"}},
		{"arm", "arm64", 0, nil, []string{"c7g.xlarge", "r7g.xlarge"}},
		{"both", "any", 0, nil, []string{"c7i.xlarge", "m7i.xlarge", "q7i.xlarge", "c7g.xlarge", "r7g.xlarge"}},
		{"memory", "any", 16, nil, []string{"m7i.xlarge", "r7g.xlarge"}},
		{"boundary", "any", 8, nil, []string{"c7i.xlarge", "m7i.xlarge", "c7g.xlarge", "r7g.xlarge"}},
		{"negative-memory", "x86", -1, nil, []string{"c7i.xlarge", "m7i.xlarge", "q7i.xlarge"}},
		{"override", "ignored", 0, []string{"r7i", "c7g", "r7i"}, []string{"r7i.xlarge", "c7g.xlarge"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, req := demoConfig(), demoRequest()
			cfg.FamiliesX86, cfg.MaxCandidates = []string{"c7i", "m7i", "q7i"}, 10
			req.Arch, req.MemGiB, req.Families = tc.arch, tc.memory, tc.families
			var rows []map[string]string
			for _, family := range []string{"c7i", "m7i", "q7i", "c7g", "r7g", "r7i"} {
				rows = append(rows, priceRow(family+".xlarge", "zone-demo-a", "0.12", "2026-10-01T02:00:00Z"))
			}
			fake := priceFake(t, rows...)
			got, err := New(cfg, fake, demoOptions()).Candidates(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			call := oneCall(t, fake, "aws", "describe-spot-price-history")
			wantArgs(t, flagValues(t, call.Args, "--instance-types"), tc.want)
			if len(got) != len(tc.want) {
				t.Fatal("returned rows escaped the family filter")
			}
			allowed := make(map[string]bool)
			for _, name := range tc.want {
				allowed[name] = true
			}
			for _, c := range got {
				arch := "x86"
				if c.Type == "c7g.xlarge" || c.Type == "r7g.xlarge" {
					arch = "arm64"
				}
				if !allowed[c.Type] || c.Arch != arch || c.Zone != "zone-demo-a" || c.Region != cfg.Region {
					t.Fatalf("wrong filtered candidate: %+v", c)
				}
				delete(allowed, c.Type)
			}
			if len(allowed) != 0 {
				t.Fatal("family candidate missing")
			}
		})
	}
}

func TestCandidateErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*boxcore.Request)
	}{
		{"cpu", func(r *boxcore.Request) { r.VCPU = 3 }},
		{"arch", func(r *boxcore.Request) { r.Arch = "unknown" }},
		{"memory", func(r *boxcore.Request) { r.MemGiB = 33 }},
		{"family", func(r *boxcore.Request) { r.Families = []string{""} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := demoRequest()
			tc.change(&req)
			fake := demoFake(t)
			_, err := New(demoConfig(), fake, demoOptions()).Candidates(context.Background(), req)
			wantKind(t, err, boxcore.KindOther)
			if len(fake.Calls) != 0 {
				t.Fatal("invalid picker inputs started a process")
			}
		})
	}
	for _, tc := range []struct {
		name, text string
		kind       boxcore.ErrorKind
	}{
		{"empty", `{"SpotPriceHistory":[]}`, boxcore.KindCapacity},
		{"json", `{`, boxcore.KindOther},
		{"time", jsonText(t, map[string]any{"SpotPriceHistory": []map[string]string{
			priceRow("c7i.xlarge", "zone-demo-a", "0.1", "invalid")}}), boxcore.KindOther},
		{"price", jsonText(t, map[string]any{"SpotPriceHistory": []map[string]string{
			priceRow("c7i.xlarge", "zone-demo-a", "NaN", "2026-10-01T02:00:00Z")}}), boxcore.KindOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &boxexec.Fake{Handlers: []boxexec.Handler{reply("aws", "describe-spot-price-history", tc.text)}}
			_, err := New(demoConfig(), fake, demoOptions()).Candidates(context.Background(), demoRequest())
			wantKind(t, err, tc.kind)
			if len(fake.Calls) != 1 {
				t.Fatal("price failure was retried")
			}
		})
	}
}
