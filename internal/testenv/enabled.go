//go:build laneboss_faults

// Package testenv exposes test overrides only in instrumentation builds.
package testenv

import (
	"os"
	"strconv"
)

func ClaimsDirectory() string     { return os.Getenv("LANEBOSS_TEST_CLAIMS_DIR") }
func DiscordBase() (string, bool) { return os.LookupEnv("LANEBOSS_TEST_DISCORD_BASE_URL") }

// BoxSleepScale shortens the sleeps of `laneboss box` by a factor in (0, 1]; any other value is ignored.
func BoxSleepScale() (float64, bool) {
	text, set := os.LookupEnv("LANEBOSS_TEST_BOX_SLEEP_SCALE")
	scale, err := strconv.ParseFloat(text, 64)
	if !set || err != nil || scale <= 0 || scale > 1 {
		return 0, false
	}
	return scale, true
}
