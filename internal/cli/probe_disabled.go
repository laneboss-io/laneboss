//go:build !laneboss_faults

package cli

import "io"

func runLaneProbe([]string, io.Reader, io.Writer, io.Writer) (int, bool) { return 0, false }
