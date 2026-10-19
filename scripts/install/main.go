// The install helper publishes a source-built launcher and its plugin assets.
// It is built temporarily by scripts/install.sh and is not installed.
package main

import (
	"fmt"
	"os"

	"laneboss.io/laneboss/internal/installation"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "install: expected source directory, prefix and built launcher")
		os.Exit(2)
	}
	if err := installation.Install(os.Args[1], os.Args[2], os.Args[3], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "install: "+err.Error())
		os.Exit(2)
	}
}
