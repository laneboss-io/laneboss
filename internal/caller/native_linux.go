package caller

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"laneboss.io/laneboss/internal/faults"
)

// Session records always use kernel start ticks, even in portable run mode.
func nativeProcess(pid int) (process, error) {
	data, err := faults.ProcStat(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return process{}, nil
	}
	if err != nil {
		return process{}, err
	}
	return parseProc(pid, data)
}
