package boxcore

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorText(t *testing.T) {
	secret := errors.New("SECRET-ARGV")
	cases := []struct {
		name   string
		op     string
		code   string
		detail string
		want   string
	}{
		{"full", "launch", "Busy", "try later", "launch: Busy: try later"},
		{"op-code", "launch", "Busy", "", "launch: Busy"},
		{"op-detail", "launch", "", "try later", "launch: try later"},
		{"code-detail", "", "Busy", "try later", "Busy: try later"},
		{"op-only", "launch", "", "", "launch"},
		{"code-only", "", "Busy", "", "Busy"},
		{"detail-only", "", "", "try later", "try later"},
		{"empty", "", "", "", "quota"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewError(KindQuota, tc.op, tc.code, tc.detail, secret)
			if e.Kind != KindQuota || e.Op != tc.op || e.Code != tc.code || e.Detail != tc.detail || e.Err != secret {
				t.Fatal("NewError lost a field")
			}
			got := e.Error()
			if strings.Contains(got, secret.Error()) {
				t.Fatal("Error exposed the wrapped error text")
			}
			if got != tc.want {
				t.Fatalf("Error = %q, want %q", got, tc.want)
			}
		})
	}
}
