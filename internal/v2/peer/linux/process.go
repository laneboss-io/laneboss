package linux

import (
	"bytes"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

func processTicks(pid int, data []byte) (string, error) {
	open, close := bytes.IndexByte(data, '('), bytes.LastIndexByte(data, ')')
	if open < 1 || close <= open || strings.TrimSpace(string(data[:open])) != strconv.Itoa(pid) {
		return "", peerError(api.CodeUnauthenticated, "invalid kernel process record")
	}
	fields := strings.Fields(string(data[close+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
		return "", peerError(api.CodeUnauthenticated, "kernel process record is not live")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return "", peerError(api.CodeUnauthenticated, "invalid process generation")
	}
	return strconv.FormatUint(ticks, 10), nil
}

func checkIDs(data []byte, uid, gid uint32) error {
	foundUID, foundGID := false, false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != "Uid:" && fields[0] != "Gid:") {
			continue
		}
		if len(fields) != 5 {
			return peerError(api.CodeUnauthenticated, "invalid kernel credentials")
		}
		expected := uid
		if fields[0] == "Uid:" {
			if foundUID {
				return peerError(api.CodeUnauthenticated, "duplicate kernel UID record")
			}
			foundUID = true
		} else {
			if foundGID {
				return peerError(api.CodeUnauthenticated, "duplicate kernel GID record")
			}
			foundGID, expected = true, gid
		}
		for _, field := range fields[1:] {
			value, err := strconv.ParseUint(field, 10, 32)
			if err != nil || uint32(value) != expected {
				return peerError(api.CodeUnauthenticated, "kernel credentials drifted")
			}
		}
	}
	if !foundUID || !foundGID {
		return peerError(api.CodeUnauthenticated, "kernel credentials are missing")
	}
	return nil
}

func unifiedGroup(data []byte) (string, error) {
	group := ""
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "0::/") || group != "" {
			return "", peerError(api.CodeContainmentUnknown, "unified cgroup v2 is required")
		}
		group = strings.TrimPrefix(line, "0::/")
		if group == "" {
			group = "."
		}
	}
	if group == "" {
		return "", peerError(api.CodeContainmentUnknown, "kernel cgroup record is missing")
	}
	return group, nil
}
