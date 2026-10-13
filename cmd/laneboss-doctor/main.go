// Command laneboss-doctor is the Go implementation of `laneboss doctor`. The Python launcher forwards
// `laneboss doctor ...` here, unchanged, when LANEBOSS_DOCTOR_GO_BIN names this binary.
package main

import (
	"os"

	"laneboss.io/laneboss/internal/doctor"
)

func main() {
	os.Exit(doctor.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
