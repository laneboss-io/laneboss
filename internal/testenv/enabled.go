//go:build laneboss_faults

// Package testenv exposes test overrides only in instrumentation builds.
package testenv

import "os"

func ClaimsDirectory() string     { return os.Getenv("LANEBOSS_TEST_CLAIMS_DIR") }
func DiscordBase() (string, bool) { return os.LookupEnv("LANEBOSS_TEST_DISCORD_BASE_URL") }
