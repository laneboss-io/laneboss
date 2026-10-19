package ticket

import (
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// ReadFile opens the caller's handoff file once. Nonblocking open prevents a
// FIFO from hanging before the regular-file check, and NOFOLLOW rejects links.
// No error includes the path or any input byte. The file is not removed: only
// the human may collect their handoff file after reviewing registration.
func ReadFile(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", refusal(InvalidFile)
	}
	f := os.NewFile(uintptr(fd), "registration ticket")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 256 {
		return "", refusal(InvalidFile)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", refusal(InvalidFile)
	}
	data, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil || len(data) > 256 {
		return "", refusal(InvalidFile)
	}
	raw := strings.TrimSuffix(string(data), "\n")
	if !Valid(raw) {
		return "", refusal(InvalidFile)
	}
	return raw, nil
}
