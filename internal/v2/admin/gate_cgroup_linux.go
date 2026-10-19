//go:build linux

package admin

import (
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type nativeCounter struct {
	value uint64
	known bool
}

type nativeCgroupSnapshot struct {
	oom, oomKill, pidsMax nativeCounter
	memory, processes     string
}

func readNativeCgroupSnapshot(fd int) nativeCgroupSnapshot {
	result := nativeCgroupSnapshot{memory: "unavailable", processes: "unavailable"}
	var info unix.Stat_t
	var filesystem unix.Statfs_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR ||
		unix.Fstatfs(fd, &filesystem) != nil || filesystem.Type != unix.CGROUP2_SUPER_MAGIC {
		return result
	}
	read := func(name string) []byte {
		raw, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil
		}
		file := os.NewFile(uintptr(raw), "cgroup-diagnostic")
		data, readErr := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) > 4096 {
			return nil
		}
		return data
	}
	if values, ok := parseNativeEvents(read("memory.events")); ok {
		result.oom.value, result.oom.known = values["oom"]
		result.oomKill.value, result.oomKill.known = values["oom_kill"]
	}
	if values, ok := parseNativeEvents(read("pids.events")); ok {
		result.pidsMax.value, result.pidsMax.known = values["max"]
	}
	result.memory = nativeLimitRange(read("memory.max"), true)
	result.processes = nativeLimitRange(read("pids.max"), false)
	return result
}

func parseNativeEvents(data []byte) (map[string]uint64, bool) {
	if len(data) == 0 || len(data) > 4096 {
		return nil, false
	}
	result := map[string]uint64{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) > 64 {
			return nil, false
		}
		for _, letter := range fields[0] {
			if letter != '_' && (letter < 'a' || letter > 'z') {
				return nil, false
			}
		}
		if _, exists := result[fields[0]]; exists {
			return nil, false
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return nil, false
		}
		result[fields[0]] = value
	}
	return result, true
}

func nativeLimitRange(data []byte, memory bool) string {
	fields := strings.Fields(string(data))
	if len(fields) != 1 {
		return "unavailable"
	}
	if fields[0] == "max" {
		return "unlimited"
	}
	value, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return "unavailable"
	}
	if memory {
		if value < 64<<20 {
			return "below_64MiB"
		}
		if value < 256<<20 {
			return "64_to_255MiB"
		}
		return "at_least_256MiB"
	}
	if value < 16 {
		return "below_16"
	}
	if value < 64 {
		return "16_to_63"
	}
	return "at_least_64"
}

func (c nativeCounter) fact() string {
	if !c.known {
		return "unavailable"
	}
	if c.value == 0 {
		return "zero"
	}
	return "positive"
}

func nativeCounterDelta(before, after nativeCounter) string {
	if !before.known || !after.known {
		return "unavailable"
	}
	if after.value > before.value {
		return "increased"
	}
	if after.value < before.value {
		return "decreased"
	}
	return "unchanged"
}

func nativeCounterFacts(name string, before, after nativeCounter) string {
	return name + "_before=" + before.fact() + "; " + name + "_after=" + after.fact() + "; " + name + "_delta=" + nativeCounterDelta(before, after)
}

func (before nativeCgroupSnapshot) facts(after nativeCgroupSnapshot) string {
	return nativeCounterFacts("oom", before.oom, after.oom) + "; " + nativeCounterFacts("oom_kill", before.oomKill, after.oomKill) + "; " +
		nativeCounterFacts("pids_max_event", before.pidsMax, after.pidsMax) + "; memory_max=" + nativeLimitFact(before.memory) + "->" + nativeLimitFact(after.memory) +
		"; pids_max=" + nativeLimitFact(before.processes) + "->" + nativeLimitFact(after.processes)
}

func nativeLimitFact(value string) string {
	switch value {
	case "unlimited", "below_64MiB", "64_to_255MiB", "at_least_256MiB", "below_16", "16_to_63", "at_least_64":
		return value
	default:
		return "unavailable"
	}
}
