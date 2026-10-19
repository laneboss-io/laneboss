//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// The root tag keeps native cgroup setup out of the unprivileged unit set.
func TestAgentContainment(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("agent containment requires the disposable Linux root test")
	}
	// Register cleanup before starting the process, so its native wait and
	// descriptor cleanup finish before removing the real cgroup directory.
	group := cleanupCgroup(t, testBinding(), "gate-containment")
	m, open, gate, output, _ := retainedGateFixture(t)
	record, err := m.find(open.Binding.Record.UIDLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(group)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := writeControl(root, "cgroup.procs", strconv.Itoa(gate.PID())); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := gate.Close(); err != nil {
			t.Error(err)
		}
		if _, err := gate.Stop(ctx, gateHandle(record)); err != nil {
			t.Error(err)
		}
	})
	checkAgentContainment(t, m, open, gate, output)
}
