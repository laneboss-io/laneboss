//go:build linux && laneboss_gate_integration

package admin

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

type processCapabilityCanary struct {
	ThreadChanged bool
	OtherBitsKept bool
	MainEffective bool
	MainPermitted bool
	MainBounding  bool
	MainEffDrop   bool
	MainPrmDrop   bool
	Error         string
}

func init() {
	if len(os.Args) != 2 || os.Args[1] != "admin-process-capability-canary" {
		return
	}
	// init runs on the startup thread. Keep that leader reserved while a
	// different locked thread loses exactly one effective capability.
	runtime.LockOSThread()
	if os.Geteuid() != 0 || unix.Gettid() != os.Getpid() {
		os.Exit(41)
	}
	completed := make(chan processCapabilityCanary)
	go func() {
		runtime.LockOSThread()
		// Never Unlock: even a failed mutation attempt retires this thread.
		result := processCapabilityCanary{}
		defer func() { completed <- result }()
		if unix.Gettid() == os.Getpid() {
			result.Error = "not an independent thread"
			return
		}
		header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var before [2]unix.CapUserData
		if unix.Capget(&header, &before[0]) != nil || before[0].Effective&(1<<unix.CAP_SETUID) == 0 {
			result.Error = "capability control unavailable"
			return
		}
		changed := before
		changed[0].Effective &^= 1 << unix.CAP_SETUID
		if unix.Capset(&header, &changed[0]) != nil {
			result.Error = "thread capability mutation refused"
			return
		}
		var after [2]unix.CapUserData
		if unix.Capget(&header, &after[0]) != nil {
			result.Error = "thread capability observation unavailable"
			return
		}
		result.ThreadChanged = before[0].Effective^after[0].Effective == 1<<unix.CAP_SETUID
		result.OtherBitsKept = after == changed
		main, err := readProcessSetUID()
		if err != nil {
			result.Error = "main-thread observation unavailable"
			return
		}
		result.MainEffective, result.MainPermitted, result.MainBounding = main.effective, main.permitted, main.bounding
	}()
	result := <-completed
	if result.Error == "" {
		header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var before [2]unix.CapUserData
		if unix.Capget(&header, &before[0]) != nil || before[0].Effective&(1<<unix.CAP_SETUID) == 0 {
			result.Error = "main-thread capability control unavailable"
		} else {
			changed := before
			changed[0].Effective &^= 1 << unix.CAP_SETUID
			if unix.Capset(&header, &changed[0]) != nil {
				result.Error = "main-thread effective mutation refused"
			} else {
				observed, err := readProcessSetUID()
				var after [2]unix.CapUserData
				if err != nil || unix.Capget(&header, &after[0]) != nil {
					result.Error = "main-thread effective observation unavailable"
				} else {
					result.MainEffDrop = after == changed && !observed.effective && observed.permitted && observed.bounding
					changed[0].Permitted &^= 1 << unix.CAP_SETUID
					if unix.Capset(&header, &changed[0]) != nil {
						result.Error = "main-thread permitted mutation refused"
					} else {
						observed, err := readProcessSetUID()
						if err != nil || unix.Capget(&header, &after[0]) != nil {
							result.Error = "main-thread permitted observation unavailable"
						} else {
							result.MainPrmDrop = after == changed && !observed.effective && !observed.permitted && observed.bounding
						}
					}
				}
			}
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(42)
	}
	os.Exit(0)
}

func TestInstalledProcessThreadCaps(t *testing.T) {
	_ = installedGateBinding(t)
	command := exec.Command("/proc/self/exe", "admin-process-capability-canary")
	command.Env = []string{}
	data, err := command.Output()
	var measured processCapabilityCanary
	if err != nil || json.Unmarshal(data, &measured) != nil || measured.Error != "" || !measured.ThreadChanged || !measured.OtherBitsKept {
		t.Fatal("native capability canary did not reach its exact one-bit thread mutation")
	}
	if !measured.MainEffective || !measured.MainPermitted || !measured.MainBounding {
		t.Fatal("acceptance: process capability observation followed the polluted launch thread")
	}
	if !measured.MainEffDrop || !measured.MainPrmDrop {
		t.Fatal("acceptance: process capability observation hid actual leader capability loss")
	}
}
