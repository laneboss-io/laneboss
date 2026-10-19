//go:build linux

package admin

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// The service drains its per-lease listener before retirement. Native readback
// checks both the protected pathname and the kernel table: unlinking a live
// Unix socket is not evidence that its endpoint or connections ended.
func (m *leaseManager) archiveSocketCount(ctx context.Context, id api.ID) (uint64, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	if !validID(id) {
		return 0, failure(api.CodeInvalid, "invalid archive endpoint selector")
	}
	if err := protectedPath(m.binding.runtimePath(), true); err != nil {
		return 0, err
	}
	base := filepath.Join(m.binding.runtimePath(), "workers")
	name := filepath.Join(base, string(id)+".sock")
	service, err := workerServiceBinding(m.binding)
	if err != nil {
		return 0, err
	}
	serviceName := filepath.Join(filepath.Dir(service.Socket), "workers", string(id)+".sock")
	var count uint64
	if _, err := os.Lstat(base); err == nil {
		parent, err := pinNativeMount(base, "", true, false, false, m.binding.Service.UID, m.binding.Service.GID)
		if err != nil {
			return 0, err
		}
		var st unix.Stat_t
		statErr, closeErr := unix.Fstat(int(parent.file.Fd()), &st), parent.file.Close()
		if statErr != nil || closeErr != nil || st.Mode&07777 != 0700 {
			return 0, failure(api.CodeIntegrity, "archive endpoint parent changed its private mode")
		}
		if _, err := os.Lstat(name); err == nil {
			count++
		} else if !errors.Is(err, os.ErrNotExist) {
			return 0, failure(api.CodeContainmentUnknown, "archive endpoint namespace is unreadable")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, failure(api.CodeContainmentUnknown, "archive endpoint parent is unreadable")
	}
	file, err := os.Open("/proc/net/unix")
	if err != nil {
		return 0, failure(api.CodeContainmentUnknown, "archive endpoint kernel inventory is unreadable")
	}
	kernel, readErr := archiveSocketInventory(ctx, file, name, serviceName)
	closeErr := file.Close()
	if readErr != nil {
		return 0, readErr
	}
	if closeErr != nil {
		return 0, failure(api.CodeContainmentUnknown, "archive endpoint kernel inventory is incomplete")
	}
	count += kernel
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	if count != 0 {
		return count, failure(api.CodeContainmentUnknown, "archive retirement still has a native socket endpoint")
	}
	return count, nil
}

// Bound each kernel record, never the aggregate inventory. A match is retained
// only after the entire stream ends cleanly; errors and partial final records
// cannot turn an unscanned suffix into evidence of absence.
func archiveSocketInventory(ctx context.Context, input io.Reader, name string, serviceNames ...string) (uint64, error) {
	names := append([]string{name}, serviceNames...)
	reader := bufio.NewReaderSize(input, 4096)
	header := true
	var count uint64
	for {
		if err := contextError(ctx); err != nil {
			return 0, err
		}
		raw, err := reader.ReadSlice('\n')
		if err == io.EOF && len(raw) == 0 && !header {
			return count, nil
		}
		if err != nil {
			return 0, failure(api.CodeContainmentUnknown, "archive endpoint kernel inventory is incomplete")
		}
		line := strings.TrimSuffix(string(raw), "\n")
		if header {
			if strings.Join(strings.Fields(line), " ") != "Num RefCount Protocol Flags Type St Inode Path" {
				return 0, failure(api.CodeContainmentUnknown, "archive endpoint kernel inventory has an unknown shape")
			}
			header = false
			continue
		}
		for column := 0; column < 7; column++ {
			line = strings.TrimLeft(line, " \t")
			end := strings.IndexAny(line, " \t")
			if end < 0 {
				end = len(line)
			}
			field := line[:end]
			base := 16
			if column == 0 {
				if !strings.HasSuffix(field, ":") {
					return 0, failure(api.CodeContainmentUnknown, "archive endpoint kernel record is incomplete")
				}
				field = strings.TrimSuffix(field, ":")
			}
			if column == 6 {
				base = 10
			}
			if _, err := strconv.ParseUint(field, base, 64); err != nil {
				return 0, failure(api.CodeContainmentUnknown, "archive endpoint kernel record is incomplete")
			}
			line = line[end:]
		}
		// The service listener and helper may use different runtime parents.
		// Match the exact issued lease path in either protected tree, including a
		// live endpoint whose pathname has been unlinked. Keep path spacing
		// intact after the seven validated kernel fields.
		socketPath := strings.TrimLeft(line, " \t")
		if slices.Contains(names, strings.TrimSuffix(socketPath, " (deleted)")) {
			count++
		}
	}
}
