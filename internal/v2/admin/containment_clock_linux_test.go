//go:build linux

package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/pollgate"
)

func TestContainmentClock(t *testing.T) {
	stamp, err := containmentNow()
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []int64{0, stamp + int64(time.Hour)} {
		if _, err := containmentExpiry(invalid); err == nil {
			t.Fatal("invalid helper clock became authority")
		}
	}
	until, err := containmentExpiry(stamp - int64(120*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	var memo pollgate.Memo[string]
	_, _, err = memo.EvalTimed(context.Background(), "lease", func(context.Context) (string, time.Time, error) {
		return "lease", until, nil
	})
	if !errors.Is(err, pollgate.ErrExpired) {
		t.Fatal("transport-aged helper observation received a new lifetime", err)
	}
}
