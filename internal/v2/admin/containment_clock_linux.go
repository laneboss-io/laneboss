//go:build linux

package admin

import (
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/pollgate"
)

// Both authenticated endpoints run on the same host and kernel boot. BOOTTIME
// includes suspend and avoids wall-clock changes or a renewed lifetime at receipt.
func containmentNow() (int64, error) {
	var stamp unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &stamp); err != nil {
		return 0, failure(api.CodeUnavailable, "containment observation clock is unavailable")
	}
	return stamp.Nano(), nil
}

func containmentExpiry(observed int64) (time.Time, error) {
	received := time.Now()
	now, err := containmentNow()
	if err != nil {
		return time.Time{}, err
	}
	if observed <= 0 || observed > now {
		return time.Time{}, failure(api.CodeIntegrity, "helper containment observation has no valid host clock")
	}
	return received.Add(pollgate.VerdictAge - time.Duration(now-observed)), nil
}
