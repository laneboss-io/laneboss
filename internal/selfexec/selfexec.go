// Package selfexec keeps worker invocations compatible with both the unified
// launcher and the per-group binaries retained for the migration test harness.
package selfexec

var unified bool

// UseUnifiedBinary is called once by cmd/laneboss, before dispatch or workers.
func UseUnifiedBinary() { unified = true }

// Args returns arguments for a new invocation of the current executable.
func Args(group string, args ...string) []string {
	if unified {
		return append([]string{group}, args...)
	}
	return args
}
