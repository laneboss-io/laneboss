// Command laneboss-doctor is retained for the GO_GROUPS migration harness.
// The installed laneboss binary calls the same internal command entry points.
package main

import (
	"os"

	"laneboss.io/laneboss/internal/doctor"
)

func main() {
	os.Exit(doctor.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
