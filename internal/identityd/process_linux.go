package identityd

import (
	"bytes"
	"os"
	"strconv"
	"strings"
)

func nativeProcess(pid int) (process, error) {
	if pid <= 1 {
		return process{}, processUnavailable()
	}
	path := "/proc/" + strconv.Itoa(pid) + "/"
	first, err := os.ReadFile(path + "stat")
	if err != nil {
		return process{}, err
	}
	parent, ticks, err := procStat(pid, first)
	if err != nil {
		return process{}, err
	}
	status, err := os.ReadFile(path + "status")
	if err != nil {
		return process{}, err
	}
	var uid, gid uint32
	foundUID, foundGID := false, false
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] != "Uid:" && fields[0] != "Gid:" {
			continue
		}
		value, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return process{}, processUnavailable()
		}
		if fields[0] == "Uid:" {
			uid, foundUID = uint32(value), true
		} else {
			gid, foundGID = uint32(value), true
		}
	}
	if !foundUID || !foundGID {
		return process{}, processUnavailable()
	}
	last, err := os.ReadFile(path + "stat")
	if err != nil {
		return process{}, err
	}
	lastParent, lastTicks, err := procStat(pid, last)
	if err != nil || parent != lastParent || ticks != lastTicks {
		return process{}, processUnavailable()
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) == "" {
		return process{}, processUnavailable()
	}
	return process{Peer: Peer{PID: pid, UID: uid, GID: gid, Start: strings.TrimSpace(string(boot)) + ":" + ticks}, Parent: parent}, nil
}

func processTerminal(pid int) (int, bool, string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false, "", err
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return 0, false, "", processUnavailable()
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 5 {
		return 0, false, "", processUnavailable()
	}
	sid, err := strconv.Atoi(fields[3])
	if err != nil {
		return 0, false, "", err
	}
	tty, err := strconv.ParseInt(fields[4], 10, 64)
	if err != nil {
		return 0, false, "", err
	}
	start := bytes.IndexByte(data, '(')
	if start < 0 || start >= end {
		return 0, false, "", processUnavailable()
	}
	return sid, tty != 0, sharedProgram(string(data[start+1 : end])), nil
}

func procStat(pid int, data []byte) (int, string, error) {
	open, close := bytes.IndexByte(data, '('), bytes.LastIndexByte(data, ')')
	if open < 1 || close <= open || strings.TrimSpace(string(data[:open])) != strconv.Itoa(pid) {
		return 0, "", processUnavailable()
	}
	fields := strings.Fields(string(data[close+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return 0, "", processUnavailable()
	}
	parent, err := strconv.Atoi(fields[1])
	ticks, tickError := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || parent < 0 || tickError != nil || ticks == 0 {
		return 0, "", processUnavailable()
	}
	return parent, fields[19], nil
}
