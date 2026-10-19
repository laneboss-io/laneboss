//go:build linux

package wire

import "testing"

// Unit data for the kernel-membership parser; installed root helper identity
// still requires the native cgroup/socket/artifact checks and installed E2E.
func TestAdminMembership(t *testing.T) {
	unit := "/system.slice/laneboss-helper@" + "frame-case.service/control"
	actual, members, pid := []byte("0::"+unit+"\n"), []byte("4321\n"), 4321
	if err := administratorMembership(actual, members, unit, pid); err != nil {
		t.Fatal("fixed helper membership control failed", err)
	}
	for _, mode := range []string{"unit", "pid", "shared", "duplicate", "missing"} {
		t.Run(mode, func(t *testing.T) {
			a, m, p := actual, members, pid
			switch mode {
			case "unit":
				a = []byte("0::" + unit + "-other\n")
			case "pid":
				p++
			case "shared":
				m = []byte("4321\n4322\n")
			case "duplicate":
				a = append(append([]byte{}, actual...), actual...)
			case "missing":
				a = []byte("1:legacy:/other\n")
			}
			if err := administratorMembership(a, m, unit, p); err == nil {
				t.Fatal("administrator accepted foreign helper membership", mode)
			}
		})
	}
}
