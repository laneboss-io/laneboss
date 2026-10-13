// Command laneboss-disk is the Go implementation of `laneboss disk`. The Python launcher forwards
// `laneboss disk ...` here, unchanged, when LANEBOSS_DISK_GO_BIN names this binary.
package main

import (
	"os"

	"laneboss.io/laneboss/internal/disk"
)

func main() {
	os.Exit(disk.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
