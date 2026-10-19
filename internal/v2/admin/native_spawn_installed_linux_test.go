//go:build linux && laneboss_gate_integration

package admin

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestInstalledNativeSpawnRefusal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("installed native spawn refusal requires its isolated root unit")
	}
	_ = installedGateBinding(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	network, err := newEmptyNetworkNamespace(ctx)
	if err != nil {
		t.Fatal("installed native spawn refusal could not create its real network namespace")
	}
	defer func() {
		if err := network.Close(); err != nil {
			t.Error("installed native spawn refusal could not close its network descriptor")
		}
	}()
	private, err := randomID("missing-network-executable-")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(privateTestDir(t), string(private)), string(private))
	cmd.Env = []string{}
	cmd.SysProcAttr = nativeGateAttributes(uint32(os.Geteuid()), uint32(os.Getegid()), missingNativeCgroupFD(t))
	err = startInNetworkNamespace(cmd, network)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Owner != "lb-v2-admin" || typed.Code != api.CodePrerequisite ||
		!strings.HasPrefix(typed.Message, "kernel refused confined gate creation (spawn errno=") || !strings.Contains(typed.Message, "; clone3 size-zero=") || cmd.Process != nil {
		t.Fatal("acceptance: retained-network spawn lost its safe failure or restoration priority")
	}
	if strings.Contains(err.Error(), string(private)) {
		t.Fatal("acceptance: retained-network spawn disclosed private executable data")
	}
	if !strings.Contains(typed.Message, "helper CAP_SETUID=") || !strings.Contains(typed.Message, "helper nnp=") || !strings.Contains(typed.Message, "cgroup=unavailable(EBADF)") {
		t.Fatal("acceptance: retained-network spawn lost its read-only setup observations")
	}
	if !strings.Contains(typed.Message, "process CAP_SETUID CapEff=") || !strings.Contains(typed.Message, ", CapPrm=") || !strings.Contains(typed.Message, ", CapBnd=") {
		t.Fatal("acceptance: retained-network spawn lost its independent main-thread observation")
	}
}
