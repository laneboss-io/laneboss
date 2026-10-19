package boxcfg

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
)

func loadLedger(s section) boxcore.LedgerConfig {
	s.allowed("path schema registry")
	return boxcore.LedgerConfig{
		Path: s.path("path", filepath.Join(s.v.env.StateHome, "boxes", "ledger.jsonl"), false, false),
		Schema: s.text("schema", "laneboss-box-event/v1", false, func(text string) bool {
			return boundedText(text, 1, 64)
		}),
		Registry: s.path("registry", "", false, true),
	}
}

func loadDefaults(s section) boxcore.Defaults {
	s.allowed("provider vcpu mem_gib arch root_gb idle_min hard_min " +
		"cost_cap_usd disk_usd_gb_month name_prefix run_dir")
	d := boxcore.Defaults{
		Provider:       s.text("provider", "", false, choice("aws", "gcp")),
		VCPU:           s.integer("vcpu", 2, false, 2, 64),
		MemGiB:         s.integer("mem_gib", 4, false, 0, 2048),
		Arch:           s.text("arch", "any", false, choice("x86", "arm64", "any")),
		RootGB:         s.integer("root_gb", 150, false, 8, 2000),
		IdleMin:        s.integer("idle_min", 30, false, 1, 1440),
		HardMin:        s.integer("hard_min", 360, false, 10, 10080),
		CostCapUSD:     s.number("cost_cap_usd", 5, false, 0, 10000, true),
		DiskUSDGBMonth: s.number("disk_usd_gb_month", 0.10, false, 0, 10, false),
		NamePrefix: s.text("name_prefix", "lb-", false, func(text string) bool {
			return grammar(`[a-z][a-z0-9-]{0,15}`)(text) && strings.HasSuffix(text, "-")
		}),
		RunDir: s.path("run_dir", filepath.Join(s.v.env.StateHome, "boxes", "runs"), false, false),
	}
	if !slices.Contains([]int{2, 4, 8, 16, 32, 48, 64}, d.VCPU) {
		s.v.fail(s.key("vcpu"), "must be an allowed processor count")
	}
	if d.IdleMin > d.HardMin {
		s.v.fail(s.key("idle_min"), "must not exceed the hard limit")
	}
	return d
}

func guestPath(text string) bool {
	if !filepath.IsAbs(text) || !boundedText(text, 1, 200) || strings.ContainsAny(text, "' ") {
		return false
	}
	return !slices.Contains(strings.Split(text, "/"), "..")
}

func guestPaths(s section, key string, fallback []string) []string {
	paths := s.texts(key, fallback, false, 1, 8, nil)
	for i, value := range paths {
		item := fmt.Sprintf("%s[%d]", key, i)
		// Validate before cleaning so a forbidden parent segment is not erased.
		if slices.Contains(strings.Split(value, "/"), "..") {
			s.v.fail(s.key(item), "parent path segments are forbidden")
		}
		paths[i] = s.expand(item, value, false)
		if !guestPath(paths[i]) {
			s.v.fail(s.key(item), "must be a safe absolute guest path")
		}
	}
	return paths
}

func loadGuest(s section) boxcore.GuestConfig {
	s.allowed("done_files busy_files out_dir")
	g := boxcore.GuestConfig{
		DoneFiles: guestPaths(s, "done_files", []string{"/var/tmp/lb-done"}),
		BusyFiles: guestPaths(s, "busy_files", []string{"/var/tmp/lb-busy"}),
	}
	raw := s.text("out_dir", "/var/lib/lb-box/out", false, nil)
	if slices.Contains(strings.Split(raw, "/"), "..") {
		s.v.fail(s.key("out_dir"), "parent path segments are forbidden")
	}
	g.OutDir = s.expand("out_dir", raw, false)
	if !guestPath(g.OutDir) || filepath.Clean(g.OutDir) == "/" {
		s.v.fail(s.key("out_dir"), "must be a safe guest output directory")
	}
	for _, done := range g.DoneFiles {
		for _, busy := range g.BusyFiles {
			if filepath.Clean(done) == filepath.Clean(busy) {
				s.v.fail(s.key("busy_files"), "must not share a path with done files")
			}
		}
	}
	for _, path := range append(slices.Clone(g.DoneFiles), g.BusyFiles...) {
		if filepath.Clean(path) == filepath.Clean(g.OutDir) {
			s.v.fail(s.key("out_dir"), "must not equal a done or busy file")
		}
	}
	return g
}
