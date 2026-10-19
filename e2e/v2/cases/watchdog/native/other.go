//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "watchdog native fixture requires the authorized Linux installation")
	os.Exit(69)
}
