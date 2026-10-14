//go:build linux

package disk

import (
	"os"
	"syscall"
)

func filesystemStats(f *os.File) (blocks, free, available, fragment uint64, err error) {
	var stats syscall.Statfs_t
	err = syscall.Fstatfs(int(f.Fd()), &stats)
	return stats.Blocks, stats.Bfree, stats.Bavail, uint64(stats.Frsize), err
}
