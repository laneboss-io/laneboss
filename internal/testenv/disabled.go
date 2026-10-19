//go:build !laneboss_faults

package testenv

func ClaimsDirectory() string        { return "" }
func DiscordBase() (string, bool)    { return "", false }
func BoxSleepScale() (float64, bool) { return 0, false }
