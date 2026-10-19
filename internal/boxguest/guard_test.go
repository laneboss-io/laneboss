package boxguest

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
)

func TestDoneOverridesBusy(t *testing.T) {
	h := newGuard(t, boxcore.GuestSpec{IdleMin: 2})
	h.write(h.spec.DoneFiles[0], "done\n", 0644)
	h.write(h.spec.BusyFiles[0], "busy\n", 0644)
	h.setTime(h.spec.BusyFiles[0], testNow)
	h.write(h.load, "8.00 8.00 8.00 1/1 1\n", 0644)
	h.env["FAKE_DOCKER_ID"] = "sprout-container"
	h.execute(testNow, "", 0)
	h.shutdowns(1)
	if !strings.Contains(readFile(t, h.log), "done marker") {
		t.Fatal("done shutdown was not logged")
	}
}

func TestSecondDoneFile(t *testing.T) {
	h := newGuard(t, boxcore.GuestSpec{})
	h.spec.DoneFiles = []string{
		filepath.Join(h.root, "first"), filepath.Join(h.root, "second"),
	}
	h.write(h.guard, GuardScript(h.spec), 0755)
	h.write(h.spec.DoneFiles[1], "done\n", 0644)
	h.execute(testNow, "", 0)
	h.shutdowns(1)
}

func TestBusyLoadEdges(t *testing.T) {
	for _, tc := range []struct {
		load string
		busy bool
	}{
		{"0.31", true}, {"0.30", false},
	} {
		t.Run(tc.load, func(t *testing.T) {
			h := newGuard(t, boxcore.GuestSpec{IdleMin: 2})
			h.write(filepath.Join(h.run, "idle-since"), "1\n", 0644)
			h.write(h.load, tc.load+" 0.00 0.00 1/1 1\n", 0644)
			h.execute(testNow, "", 0)
			if tc.busy {
				absent(t, filepath.Join(h.run, "idle-since"))
				h.shutdowns(0)
			} else {
				idleSince(h, 1)
				h.shutdowns(1)
			}
		})
	}
}

func TestBusyFileAges(t *testing.T) {
	for _, tc := range []struct {
		age  int64
		busy bool
	}{
		{599, true}, {600, false}, {601, false},
	} {
		t.Run(strconv.FormatInt(tc.age, 10), func(t *testing.T) {
			h := newGuard(t, boxcore.GuestSpec{IdleMin: 2})
			// The second busy path must work too.
			h.spec.BusyFiles = []string{
				filepath.Join(h.root, "absent-busy"),
				filepath.Join(h.root, "fresh-busy"),
			}
			h.write(h.guard, GuardScript(h.spec), 0755)
			h.write(h.spec.BusyFiles[1], "busy\n", 0644)
			h.setTime(h.spec.BusyFiles[1], testNow-tc.age)
			h.write(filepath.Join(h.run, "idle-since"), "1\n", 0644)
			h.execute(testNow, "", 0)
			if tc.busy {
				absent(t, filepath.Join(h.run, "idle-since"))
				h.shutdowns(0)
			} else {
				idleSince(h, 1)
				h.shutdowns(1)
			}
		})
	}
}

func TestBusyContainer(t *testing.T) {
	h := newGuard(t, boxcore.GuestSpec{IdleMin: 2})
	h.write(filepath.Join(h.run, "idle-since"), "1\n", 0644)
	h.env["FAKE_DOCKER_ID"] = "sprout-container"
	h.execute(testNow, "", 0)
	absent(t, filepath.Join(h.run, "idle-since"))
	h.shutdowns(0)
}

func TestProbeFailuresLog(t *testing.T) {
	for _, probe := range []string{"awk", "docker", "stat"} {
		t.Run(probe, func(t *testing.T) {
			h := newGuard(t, boxcore.GuestSpec{IdleMin: 2})
			h.write(filepath.Join(h.run, "idle-since"), "1\n", 0644)
			h.write(h.spec.BusyFiles[0], "busy\n", 0644)
			h.setTime(h.spec.BusyFiles[0], testNow)
			// A failed probe alone is not one of the proven busy signals.
			if probe != "stat" {
				h.setTime(h.spec.BusyFiles[0], testNow-601)
			}
			h.fake(probe, "exit 2\n")
			h.execute(testNow, "", 0)
			idleSince(h, 1)
			h.shutdowns(1)
			if !strings.Contains(readFile(t, h.log), "check failed") &&
				!strings.Contains(readFile(t, h.log), "stat failed") {
				t.Fatal("probe failure was not logged")
			}
		})
	}
}

func TestIdleFirstPass(t *testing.T) {
	h := newGuard(t, boxcore.GuestSpec{IdleMin: 2})
	h.execute(testNow, "", 0)
	idleSince(h, testNow)
	h.shutdowns(0)
}

func TestIdleBoundary(t *testing.T) {
	h := newGuard(t, boxcore.GuestSpec{IdleMin: 2})
	h.execute(testNow, "", 0)
	h.execute(testNow+119, "", 0)
	idleSince(h, testNow)
	h.shutdowns(0)
	h.execute(testNow+120, "", 0)
	h.shutdowns(1)
	if !strings.Contains(readFile(t, h.log), "idle 2 min: shutting down") {
		t.Fatal("idle duration was not logged")
	}
}

func TestBusyResetsIdle(t *testing.T) {
	h := newGuard(t, boxcore.GuestSpec{IdleMin: 2})
	h.execute(testNow, "", 0)
	h.write(h.load, "0.31 0.00 0.00 1/1 1\n", 0644)
	h.execute(testNow+100, "", 0)
	absent(t, filepath.Join(h.run, "idle-since"))
	h.write(h.load, "0.00 0.00 0.00 1/1 1\n", 0644)
	h.execute(testNow+120, "", 0)
	idleSince(h, testNow+120)
	h.execute(testNow+239, "", 0)
	h.shutdowns(0)
	h.execute(testNow+240, "", 0)
	h.shutdowns(1)
}

func TestModesDoNotGuard(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, mode := range []string{"sync", "final"} {
			t.Run(provider+"-"+mode, func(t *testing.T) {
				h := newGuard(t, boxcore.GuestSpec{Provider: provider})
				h.write(h.spec.DoneFiles[0], "done\n", 0644)
				h.execute(testNow, mode, 0)
				h.shutdowns(0)
				absent(t, filepath.Join(h.run, "idle-since"))
			})
		}
	}
}
