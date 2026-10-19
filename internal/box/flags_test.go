package box

import (
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcfg"
	"laneboss.io/laneboss/internal/boxcore"
)

func TestPlacementFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
		get  func(boxcore.Request) any
		want any
	}{
		{"provider", []string{"--provider", "gcp"}, func(r boxcore.Request) any { return r.Provider }, "gcp"},
		{"purpose", []string{"--purpose", "flag-purpose"}, func(r boxcore.Request) any { return r.Purpose }, "flag-purpose"},
		{"vcpu", []string{"--vcpu", "16"}, func(r boxcore.Request) any { return r.VCPU }, 16},
		{"mem", []string{"--mem-gib", "32"}, func(r boxcore.Request) any { return r.MemGiB }, 32},
		{"arch", []string{"--arch", "arm64"}, func(r boxcore.Request) any { return r.Arch }, "arm64"},
		{"families", []string{"--families", "c-demo,m-demo"}, func(r boxcore.Request) any { return r.Families }, []string{"c-demo", "m-demo"}},
		{"type", []string{"--type", "demo.large", "--zone", "demo-a"}, func(r boxcore.Request) any { return r.Type }, "demo.large"},
		{"zone", []string{"--type", "demo.large", "--zone", "demo-a"}, func(r boxcore.Request) any { return r.Zone }, "demo-a"},
		{"root", []string{"--root-gb", "80"}, func(r boxcore.Request) any { return r.RootGB }, 80},
		{"idle", []string{"--idle-min", "9"}, func(r boxcore.Request) any { return r.IdleMin }, 9},
		{"hard", []string{"--hard-min", "90"}, func(r boxcore.Request) any { return r.HardMin }, 90},
		{"cap", []string{"--cost-cap-usd", "1.25"}, func(r boxcore.Request) any { return r.CostCapUSD }, 1.25},
		{"lane", []string{"--lane", "flag-lane"}, func(r boxcore.Request) any { return r.Lane }, "flag-lane"},
		{"owner", []string{"--owner", "flag-owner"}, func(r boxcore.Request) any { return r.OwnerBasis + ":" + r.Owner }, "flag:flag-owner"},
	}
	for _, command := range []string{"launch", "run"} {
		for _, tc := range cases {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				h := newFixture(t)
				h.vars["LANEBOSS_BOX_OWNER"] = "env-owner"
				h.vars["LANEBOSS_BOX_LANE"] = "env-lane"
				args := []string{command, "--purpose", "demo"}
				if command == "run" {
					args = append(args, "--suite", "exit 0")
				}
				args = append(args, tc.args...)
				if code := h.call(args...); code != 0 {
					t.Fatalf("code=%d: %s", code, h.notes.String())
				}
				r := h.request(command)
				if !reflect.DeepEqual(tc.get(r), tc.want) || r.RunID != "" {
					t.Fatalf("request did not preserve %s: %+v", tc.name, r)
				}
			})
		}
	}
}

func TestPlacementDefaults(t *testing.T) {
	for _, command := range []string{"launch", "run"} {
		t.Run(command, func(t *testing.T) {
			h := newFixture(t)
			args := []string{command, "demo"}
			if command == "run" {
				args = append(args, "--suite", "exit 0")
			}
			if code := h.call(args...); code != 0 {
				t.Fatalf("code=%d: %s", code, h.notes.String())
			}
			want := boxcore.Request{
				Provider: "aws", Purpose: "demo", Lane: "demo", Owner: "unknown", OwnerBasis: "unknown",
				VCPU: 4, MemGiB: 8, Arch: "any", RootGB: 20, IdleMin: 15, HardMin: 120, CostCapUSD: 2,
			}
			if got := h.request(command); !reflect.DeepEqual(got, want) {
				t.Fatalf("defaults: got %+v, want %+v", got, want)
			}
		})
	}
}

func TestExplicitDefaults(t *testing.T) {
	for _, command := range []string{"launch", "run"} {
		t.Run(command, func(t *testing.T) {
			h := newFixture(t)
			h.vars["LANEBOSS_BOX_LANE"] = "env-lane"
			h.vars["LANEBOSS_BOX_OWNER"] = "env-owner"
			args := []string{command, "--purpose", "demo", "--lane", "demo", "--owner", "unknown",
				"--mem-gib", "0", "--root-gb", "20"}
			if command == "run" {
				args = append(args, "--suite", "exit 0")
			}
			if code := h.call(args...); code != 0 {
				t.Fatalf("code=%d: %s", code, h.notes.String())
			}
			r := h.request(command)
			if r.Lane != "demo" || r.Owner != "unknown" || r.OwnerBasis != "flag" || r.MemGiB != 0 || r.RootGB != 20 {
				t.Fatalf("explicit defaults were replaced: %+v", r)
			}
		})
	}
}

func TestOwnerAndLaneEnv(t *testing.T) {
	h := newFixture(t)
	h.vars["LANEBOSS_BOX_OWNER"] = "env-owner"
	h.vars["LANEBOSS_BOX_LANE"] = "env-lane"
	if code := h.call("launch", "--purpose", "demo"); code != 0 {
		t.Fatalf("code=%d: %s", code, h.notes.String())
	}
	r := h.request("launch")
	if r.Owner != "env-owner" || r.OwnerBasis != "env" || r.Lane != "env-lane" {
		t.Fatalf("environment defaults were lost: %+v", r)
	}
}

func TestProviderFallbacks(t *testing.T) {
	cases := []struct {
		name, flag, def, want string
		aws, gcp              bool
		code                  int
	}{
		{"flag", "gcp", "aws", "gcp", true, true, 0},
		{"default", "", "gcp", "gcp", true, true, 0},
		{"single-aws", "", "", "aws", true, false, 0},
		{"single-gcp", "", "", "gcp", false, true, 0},
		{"ambiguous", "", "", "", true, true, 2},
		{"none", "", "", "", false, false, 2},
		{"no-table", "gcp", "aws", "", true, false, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFixture(t)
			h.cfg.Defaults.Provider = tc.def
			if !tc.aws {
				h.cfg.AWS = nil
			}
			if !tc.gcp {
				h.cfg.GCP = nil
			}
			args := []string{"launch", "--purpose", "demo"}
			if tc.flag != "" {
				args = append(args, "--provider", tc.flag)
			}
			if code := h.call(args...); code != tc.code {
				t.Fatalf("code=%d want=%d: %s", code, tc.code, h.notes.String())
			}
			if tc.code == 0 {
				if r := h.request("launch"); r.Provider != tc.want {
					t.Fatalf("provider=%q want=%q", r.Provider, tc.want)
				}
			} else if h.built != 0 || !strings.HasPrefix(h.notes.String(), usage) {
				t.Fatal("provider refusal must precede the builder and show usage")
			}
		})
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{"SECRET-NEEDLE"},
		{"launch", "--SECRET-NEEDLE"},
		{"launch", "--owner", "SECRET-NEEDLE"},
		{"launch", "--purpose", "demo", "--type", "SECRET-NEEDLE"},
		{"launch", "--purpose", "demo", "--zone", "SECRET-NEEDLE"},
		{"launch", "--purpose", "demo", "--arch", "SECRET-NEEDLE"},
		{"launch", "--purpose", "demo", "--vcpu", "SECRET-NEEDLE"},
		{"launch", "--purpose", "SECRET-NEEDLE", "--vcpu", "3"},
		{"launch", "--purpose", "demo", "--format", "SECRET-NEEDLE"},
		{"launch", "--purpose", "SECRET-NEEDLE/path"},
		{"launch", "--purpose", "demo", "--owner", "SECRET-NEEDLE/path"},
		{"launch", "--purpose", "demo", "--lane", "SECRET-NEEDLE/path"},
		{"launch", "--purpose", "demo", "--provider", "SECRET-NEEDLE"},
		{"launch", "demo", "--purpose", "SECRET-NEEDLE"},
		{"launch", "--purpose", "demo", "--mem-gib", "-1"},
		{"launch", "--purpose", "demo", "--root-gb", "7"},
		{"launch", "--purpose", "demo", "--idle-min", "0"},
		{"launch", "--purpose", "demo", "--hard-min", "9"},
		{"launch", "--purpose", "demo", "--cost-cap-usd", "NaN"},
		{"launch", "--purpose", "demo", "--cost-cap-usd", "0"},
		{"launch", "--purpose", "demo", "--owner", ""},
	}
	for i, args := range cases {
		h := newFixture(t)
		code := h.call(args...)
		if code != 2 || h.out.Len() != 0 || h.built != 0 ||
			!strings.HasPrefix(h.notes.String(), usage) ||
			!strings.Contains(h.notes.String(), "laneboss box: error: ") ||
			strings.Contains(h.notes.String(), "SECRET-NEEDLE") {
			t.Fatalf("case %d: code=%d stdout=%q stderr=%q", i, code, h.out.String(), h.notes.String())
		}
		if i == 2 && h.loaded != "" {
			t.Fatal("missing purpose must be rejected before loading config")
		}
	}
}

func TestConfigPrecedence(t *testing.T) {
	h := newFixture(t)
	envFile := writeTemp(t, t.TempDir(), "env.toml", "org = \"example-org\"\n")
	h.vars["LANEBOSS_BOX_CONFIG"] = envFile
	if code := h.call("launch", "--purpose", "demo"); code != 0 || h.loaded != h.file {
		t.Fatalf("explicit config lost: code=%d loaded=%q", code, h.loaded)
	}
	if code := h.direct("launch", "--purpose", "demo"); code != 0 || h.loaded != envFile {
		t.Fatalf("environment config lost: code=%d loaded=%q", code, h.loaded)
	}
}

func TestConfigNames(t *testing.T) {
	h := newFixture(t)
	h.vars["LANEBOSS_CONFIG"] = "env-name"
	var options boxcfg.LocateOptions
	h.env.locate = func(o boxcfg.LocateOptions) (string, error) {
		options = o
		return h.file, nil
	}
	code := h.direct("launch", "--config", "flag-name", "--purpose", "demo")
	if code != 0 || options.ConfigName != "flag-name" {
		t.Fatalf("flag config name lost: code=%d options=%+v", code, options)
	}
	code = h.direct("launch", "--purpose", "demo")
	if code != 0 || options.ConfigName != "env-name" {
		t.Fatalf("environment config name lost: code=%d options=%+v", code, options)
	}
}

func TestNumberBounds(t *testing.T) {
	cases := []struct {
		flag, value string
		code        int
	}{
		{"vcpu", "2", 0}, {"vcpu", "8", 0}, {"vcpu", "32", 0}, {"vcpu", "48", 0}, {"vcpu", "64", 0}, {"vcpu", "3", 2}, {"vcpu", "128", 2},
		{"hard-min", "10", 0}, {"hard-min", "10080", 0}, {"hard-min", "10081", 2}, {"hard-min", "9", 2},
		{"idle-min", "1", 0}, {"idle-min", "1440", 0}, {"idle-min", "1441", 2}, {"idle-min", "0", 2},
		{"root-gb", "8", 0}, {"root-gb", "2000", 0}, {"root-gb", "2001", 2}, {"root-gb", "7", 2},
		{"cost-cap-usd", "+Inf", 2}, {"cost-cap-usd", "-1", 2},
	}
	for _, command := range []string{"launch", "run"} {
		for _, tc := range cases {
			h := newFixture(t)
			args := []string{command, "--purpose", "demo", "--" + tc.flag, tc.value}
			if command == "run" {
				args = append(args, "--suite", "exit 0")
			}
			code := h.call(args...)
			if code != tc.code || (code == 0) != (h.built == 1) {
				t.Fatalf("%s %s: code=%d want=%d stderr=%q", tc.flag, tc.value, code, tc.code, h.notes.String())
			}
		}
	}
}
