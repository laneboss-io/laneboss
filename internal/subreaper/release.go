//go:build linux && !laneboss_faults

package subreaper

// Release builds contain no subreaper mutation selector or marker writer.
func disabled() (bool, error) { return false, nil }
