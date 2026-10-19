//go:build !linux

package admin

import "context"

func RunBootstrapEntry(_ context.Context, args []string) (bool, int) {
	if len(args) == 0 || args[0] != FixedBootstrapEntry {
		return false, 0
	}
	return true, bootstrapStageCodes["entry.route"]
}
