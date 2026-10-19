//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
)

// The outer startup filesystem test launches this helper at the installed
// namespace paths. No identity reply or successful CLI call is substituted.
func TestMain(m *testing.M) {
	if os.Args[len(os.Args)-1] == "policy-start-child" {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := serve(ctx, options{Driver: "codex", Client: "/run/laneboss/client"})
		if !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "startup did not preserve its cancellation", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
