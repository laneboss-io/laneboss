//go:build linux

package admin

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNativeEventFacts(t *testing.T) {
	seed, err := randomID("events-")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(seed))
	value := binary.LittleEndian.Uint64(digest[:8])%100000 + 1
	data := []byte(fmt.Sprintf("oom %d\noom_kill %d\nmax %d\n", value, value+3, value+5))
	values, ok := parseNativeEvents(data)
	if !ok || values["oom"] != value || values["oom_kill"] != value+3 || values["max"] != value+5 {
		t.Fatal("acceptance: event parser replaced actual counter input")
	}
	for _, malformed := range []string{"", "oom -1\n", "oom 1\noom 2\n", "oom 1 extra\n", "oom " + string(seed), "oom 18446744073709551616\n"} {
		if _, ok := parseNativeEvents([]byte(malformed)); ok {
			t.Fatal("acceptance: malformed counters became observed facts")
		}
	}
	for _, cell := range []struct {
		before, after nativeCounter
		want          string
	}{
		{nativeCounter{value, true}, nativeCounter{value + 1, true}, "increased"},
		{nativeCounter{value + 1, true}, nativeCounter{value, true}, "decreased"},
		{nativeCounter{value, true}, nativeCounter{value, true}, "unchanged"},
		{nativeCounter{}, nativeCounter{value, true}, "unavailable"},
		{nativeCounter{value, true}, nativeCounter{}, "unavailable"},
	} {
		if nativeCounterDelta(cell.before, cell.after) != cell.want {
			t.Fatal("acceptance: event delta ignored unavailable or changed input")
		}
	}
	if (nativeCounter{}).fact() != "unavailable" || (nativeCounter{0, true}).fact() != "zero" || (nativeCounter{value, true}).fact() != "positive" {
		t.Fatal("acceptance: unknown or positive counters were reported as zero")
	}
	before := nativeCgroupSnapshot{oom: nativeCounter{value, true}, oomKill: nativeCounter{0, true}, pidsMax: nativeCounter{0, true}, memory: "at_least_256MiB", processes: "at_least_64"}
	after := before
	after.oomKill, after.pidsMax = nativeCounter{1, true}, nativeCounter{2, true}
	facts := before.facts(after)
	for _, want := range []string{"oom_before=positive", "oom_delta=unchanged", "oom_kill_before=zero", "oom_kill_after=positive", "oom_kill_delta=increased", "pids_max_event_delta=increased"} {
		if !strings.Contains(facts, want) {
			t.Fatal("acceptance: cgroup fact output lost before/after provenance")
		}
	}
}

func TestNativeLimitRanges(t *testing.T) {
	for _, cell := range []struct {
		name, input, want string
		memory            bool
	}{
		{"memory-low", strconv.FormatUint(64*1024*1024-1, 10), "below_64MiB", true},
		{"memory-mid", strconv.FormatUint(64*1024*1024, 10), "64_to_255MiB", true},
		{"memory-high", strconv.FormatUint(256*1024*1024, 10), "at_least_256MiB", true},
		{"memory-unlimited", "max", "unlimited", true},
		{"memory-invalid", "-1", "unavailable", true},
		{"pids-low", "15", "below_16", false},
		{"pids-mid", "16", "16_to_63", false},
		{"pids-high", "64", "at_least_64", false},
		{"pids-unlimited", "max", "unlimited", false},
		{"pids-invalid", "64 32", "unavailable", false},
	} {
		t.Run(cell.name, func(t *testing.T) {
			if nativeLimitRange([]byte(cell.input), cell.memory) != cell.want {
				t.Fatal("acceptance: native limit verdict ignored its actual bounded value")
			}
		})
	}
}

func TestNativeCgroupSource(t *testing.T) {
	root := privateTestDir(t)
	for name, data := range map[string]string{"memory.events": "oom 3\noom_kill 2\n", "pids.events": "max 4\n", "memory.max": "268435456\n", "pids.max": "64\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	file, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	actual := readNativeCgroupSnapshot(int(file.Fd()))
	if actual.oom.known || actual.oomKill.known || actual.pidsMax.known || actual.memory != "unavailable" || actual.processes != "unavailable" {
		t.Fatal("acceptance: ordinary files were reported as kernel cgroup facts")
	}
	unknown := (nativeCgroupSnapshot{}).facts(actual)
	if strings.Contains(unknown, "=zero") || strings.Contains(unknown, "=unchanged") || strings.Contains(unknown, "=->") {
		t.Fatal("acceptance: missing kernel observations became zero or empty facts")
	}
}

func TestNativeProcessSecurity(t *testing.T) {
	private, err := randomID("status-")
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range []struct{ data, seccomp, nnp string }{
		{"Seccomp:\t2\nNoNewPrivs:\t1\nName:\t" + string(private) + "\n", "filter", "set"},
		{"Seccomp:\t0\nNoNewPrivs:\t0\n", "none", "unset"},
		{"Seccomp:\t1\n", "strict", "unavailable"},
		{"Seccomp:\t2\nSeccomp:\t0\nNoNewPrivs:\t1\n", "unavailable", "unavailable"},
		{"Seccomp:\t" + string(private) + "\nNoNewPrivs:\t" + string(private) + "\n", "unavailable", "unavailable"},
		{"", "unavailable", "unavailable"},
	} {
		seccomp, nnp := nativeProcessSecurity([]byte(cell.data))
		if seccomp != cell.seccomp || nnp != cell.nnp || strings.Contains(seccomp+nnp, string(private)) {
			t.Fatal("acceptance: process security facts ignored input or exposed private status")
		}
	}
}
