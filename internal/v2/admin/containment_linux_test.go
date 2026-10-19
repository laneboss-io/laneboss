//go:build linux

package admin

import (
	"context"
	"os"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestNativeProcessGeneration(t *testing.T) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	bootID := strings.TrimSpace(string(boot))
	generation, err := processGeneration(os.Getpid(), bootID)
	if err != nil {
		t.Fatal(err)
	}
	membership, err := cgroupMembership(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	facts := api.PeerFacts{HostUID: uint32(os.Getuid()), HostGID: uint32(os.Getgid()), HostPID: os.Getpid(), ProcessGeneration: generation}
	if err := verifyContainedProcess(context.Background(), facts, bootID, membership); err != nil {
		t.Fatal(err)
	}
	facts.ProcessGeneration += "-old"
	err = verifyContainedProcess(context.Background(), facts, bootID, membership)
	if err == nil {
		t.Fatal("acceptance: stale peer generation")
	}
	requireCode(t, err, api.CodeUnauthenticated)
}
