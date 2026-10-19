//go:build !linux

package subreaper

// Enable reports that kernel orphan adoption is unavailable on this platform.
// Caller authentication is unchanged; no label or transferable token is used.
func Enable() (bool, error) { return false, nil }
