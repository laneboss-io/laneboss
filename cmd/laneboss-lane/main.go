// Command laneboss-lane is retained for the GO_GROUPS migration harness.
// The installed laneboss binary calls the same internal command entry points.
package main

import (
	"os"

	"laneboss.io/laneboss/internal/lane"
	"laneboss.io/laneboss/internal/laneturns"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "adopt", "turn", "send", "attach", "loop", "__probe":
			os.Exit(laneturns.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
		}
	}
	os.Exit(lane.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
