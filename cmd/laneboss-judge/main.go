// Command laneboss-judge is the Go implementation of `laneboss judge`. The Python launcher forwards
// `laneboss judge ...` here, unchanged, when LANEBOSS_JUDGE_GO_BIN names this binary.
package main

import (
	"os"

	"laneboss.io/laneboss/internal/judge"
)

func main() {
	os.Exit(judge.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
