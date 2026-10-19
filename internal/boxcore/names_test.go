package boxcore

import (
	"strings"
	"testing"
)

func TestPlainName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"lane", "lane-1", true},
		{"single", "a", true},
		{"max", strings.Repeat("a", 63), true},
		{"punctuation", "A0._-z", true},
		{"digit-first", "7a", true},
		{"empty", "", false},
		{"dash-first", "-a", false},
		{"dot-first", ".a", false},
		{"underscore-first", "_a", false},
		{"space", "a b", false},
		{"too-long", strings.Repeat("a", 64), false},
		{"slash", "a/b", false},
		{"comma", "a,b", false},
		{"unicode", "a界", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PlainName(tc.in); got != tc.want {
				t.Fatalf("PlainName = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestTagSafe(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"plain", "Example Org 1", true},
		{"max-runes", strings.Repeat("界", 255), true},
		{"too-many-runes", strings.Repeat("界", 256), false},
		{"empty", "", false},
		{"comma", "a,b", false},
		{"open-brace", "a{b", false},
		{"close-brace", "a}b", false},
		{"open-bracket", "a[b", false},
		{"close-bracket", "a]b", false},
		{"quote", "a\"b", false},
		{"backslash", "a\\b", false},
		{"control", "a\nb", false},
		{"unicode-control", "a\u0085b", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TagSafe(tc.in); got != tc.want {
				t.Fatalf("TagSafe = %t, want %t", got, tc.want)
			}
		})
	}
}
