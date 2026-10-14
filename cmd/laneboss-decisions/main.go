// Command laneboss-decisions is retained for the GO_GROUPS migration harness.
// The installed laneboss binary calls the same internal command entry points.
package main

import (
	"os"

	"laneboss.io/laneboss/internal/decisions"
	"laneboss.io/laneboss/internal/decisionsrv"
)

func main() {
	if code, handled := decisionsrv.TryProbe(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve", "ingest-lane", "ingest-records", "hook-history", "history-worker", "capture-decision":
			os.Exit(decisionsrv.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
		}
	}
	os.Exit(decisions.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
