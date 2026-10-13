//go:build !laneboss_faults

package orgdiscord

import "io"

func runTestProbe([]string, io.Writer, io.Writer) (int, bool) { return 0, false }
