//go:build !laneboss_faults

package decisionsrv

import "io"

// A release never handles private probes; normal command parsing refuses them.
func TryProbe([]string, io.Reader, io.Writer, io.Writer) (int, bool) { return 0, false }
