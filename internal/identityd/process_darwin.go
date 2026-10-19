package identityd

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

func nativeProcess(pid int) (process, error) {
	entries, err := unix.SysctlKinfoProcSlice("kern.proc.pid", pid)
	if err != nil {
		return process{}, err
	}
	if len(entries) != 1 {
		return process{}, processUnavailable()
	}
	entry := entries[0]
	if pid <= 1 || int(entry.Proc.P_pid) != pid || entry.Proc.P_starttime.Sec <= 0 || entry.Proc.P_starttime.Usec < 0 || entry.Proc.P_starttime.Usec >= 1000000 || entry.Proc.P_stat == 5 || entry.Eproc.Ucred.Ngroups < 1 {
		return process{}, processUnavailable()
	}
	return process{
		Peer: Peer{
			PID:   pid,
			UID:   entry.Eproc.Ucred.Uid,
			GID:   entry.Eproc.Ucred.Groups[0],
			Start: fmt.Sprintf("%d.%06d", entry.Proc.P_starttime.Sec, entry.Proc.P_starttime.Usec),
		},
		Parent: int(entry.Eproc.Ppid),
	}, nil
}

func processTerminal(pid int) (int, bool, string, error) {
	entries, err := unix.SysctlKinfoProcSlice("kern.proc.pid", pid)
	if err != nil || len(entries) != 1 {
		return 0, false, "", processUnavailable()
	}
	entry := entries[0]
	sid, err := unix.Getsid(pid)
	name := strings.TrimRight(string(entry.Proc.P_comm[:]), "\x00")
	terminal := int64(entry.Eproc.Tdev) != -1 && uint64(entry.Eproc.Tdev) != uint64(0xffffffff) && entry.Eproc.Tdev != 0
	return sid, terminal, sharedProgram(name), err
}
