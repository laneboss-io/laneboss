package boxcore

import (
	"errors"
	"math"
	"testing"
)

func TestFitHardMin(t *testing.T) {
	if MinHardMin != 10 {
		t.Fatalf("MinHardMin = %d, want 10", MinHardMin)
	}
	cases := []struct {
		name   string
		hourly float64
		hard   int
		cap    float64
		want   int
		err    error
	}{
		{"requested-bound", 0.5, 360, 5, 360, nil},
		{"reduce", 1, 360, 3, 180, nil},
		{"floor", 1, 360, 0.19, 11, nil},
		{"exact-cap", 1, 60, 1, 60, nil},
		{"minimum", 6, 360, 1, 10, nil},
		{"too-low", 1, 360, 0.1, 0, ErrCapTooLow},
		{"zero-price", 0, 60, 5, 0, ErrPriceUnknown},
		{"negative-price", -1, 60, 5, 0, ErrPriceUnknown},
		{"nan-price", math.NaN(), 60, 5, 0, ErrPriceUnknown},
		{"inf-price", math.Inf(1), 60, 5, 0, ErrPriceUnknown},
		{"neg-inf-price", math.Inf(-1), 60, 5, 0, ErrPriceUnknown},
		{"zero-cap", 1, 60, 0, 0, ErrCapTooLow},
		{"negative-cap", 1, 60, -1, 0, ErrCapTooLow},
		{"nan-cap", 1, 60, math.NaN(), 0, ErrCapTooLow},
		{"inf-cap", 1, 60, math.Inf(1), 0, ErrCapTooLow},
		{"neg-inf-cap", 1, 60, math.Inf(-1), 0, ErrCapTooLow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FitHardMin(tc.hourly, tc.hard, tc.cap)
			if got != tc.want || !errors.Is(err, tc.err) {
				t.Fatalf("FitHardMin = %d, %v; want %d, %v", got, err, tc.want, tc.err)
			}
			if err == nil && got > tc.hard {
				t.Fatal("duration grew beyond the request")
			}
		})
	}
}
