// Command laneboss-lane is the Go implementation of `laneboss lane`. The Python launcher forwards
// `laneboss lane ...` here, unchanged, when LANEBOSS_LANE_GO_BIN names this binary.
// Two packages share it: lane (start, resume, stop, status, check, mark, clean, scan, refusals, review) and
// laneturns (adopt, turn, send, attach, loop).
package main

import (
	"os"

	"laneboss.io/laneboss/internal/lane"
	"laneboss.io/laneboss/internal/laneturns"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "adopt", "turn", "send", "attach", "loop":
			os.Exit(laneturns.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
		}
	}
	os.Exit(lane.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
