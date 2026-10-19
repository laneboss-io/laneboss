package boxcore

import "testing"

func TestNormalizeUTC(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"gmt", "2026-10-14 05:06:07 GMT", "2026-10-14T05:06:07Z", true},
		{"offset", "2026-10-14 05:06:07+00:00", "2026-10-14T05:06:07Z", true},
		{"z", "2026-10-14 05:06:07Z", "2026-10-14T05:06:07Z", true},
		{"t", "2026-10-14T05:06:07Z", "2026-10-14T05:06:07Z", true},
		{"surrounded", "at 2026-10-14 05:06:07 (UTC)", "2026-10-14T05:06:07Z", true},
		{"suffix-ignored", "2026-10-14 05:06:07+08:00", "2026-10-14T05:06:07Z", true},
		{"leap-day", "2024-02-29 05:06:07", "2024-02-29T05:06:07Z", true},
		{"first", "2026-10-14 05:06:07 then 2026-10-15 00:00:00",
			"2026-10-14T05:06:07Z", true},
		{"bad-month", "2026-13-01 00:00:00", "", false},
		{"bad-day", "2026-02-30 00:00:00", "", false},
		{"bad-hour", "2026-10-14 25:00:00", "", false},
		{"bad-minute", "2026-10-14 05:60:00", "", false},
		{"bad-second", "2026-10-14 05:06:60", "", false},
		{"zero-month", "2026-00-14 05:06:07", "", false},
		{"zero-day", "2026-10-00 05:06:07", "", false},
		{"bad-first", "2026-13-01 00:00:00 then 2026-10-14 05:06:07", "", false},
		{"absent", "nonsense", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := NormalizeUTC(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("NormalizeUTC = %q, %t; want %q, %t", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestSecondsBetween(t *testing.T) {
	cases := []struct {
		name  string
		start string
		end   string
		want  int
		ok    bool
	}{
		{"positive", "2026-10-14 05:06:07 GMT", "2026-10-14T05:07:09Z", 62, true},
		{"zero", "2026-10-14T05:06:07Z", "2026-10-14 05:06:07+00:00", 0, true},
		{"negative", "2026-10-14T05:07:09Z", "2026-10-14T05:06:07Z", -62, true},
		{"bad-start", "nonsense", "2026-10-14T05:06:07Z", 0, false},
		{"bad-end", "2026-10-14T05:06:07Z", "2026-02-30 00:00:00", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SecondsBetween(tc.start, tc.end)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("SecondsBetween = %d, %t; want %d, %t", got, ok, tc.want, tc.ok)
			}
		})
	}
}
