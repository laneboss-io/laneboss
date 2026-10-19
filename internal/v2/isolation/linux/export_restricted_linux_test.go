//go:build linux

package linux

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

func init() {
	if len(os.Args) == 4 && os.Args[1] == "isolation-restricted-export" {
		if err := restrictedExport(os.Args[2], os.Args[3]); err != nil {
			if _, writeErr := os.Stdout.WriteString(restrictedExportStage); writeErr != nil {
				os.Exit(65)
			}
			os.Exit(64)
		}
		os.Exit(0)
	}
}

var restrictedExportStage = "filter"

func restrictedExport(base, kind string) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_OPENAT2},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	if errno != 0 || result != 0 {
		return unix.EIO
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, base, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC})
	if fd >= 0 {
		unix.Close(fd)
	}
	if !errors.Is(err, unix.EPERM) {
		return unix.EINVAL
	}
	restrictedExportStage = "pin"
	item, err := pinPath(base, "/work/main", false)
	if err != nil {
		return err
	}
	defer item.file.Close()
	restrictedExportStage = "inspect"
	link, err := fdpath.Inspect(int(item.file.Fd()), "link")
	if err != nil {
		return err
	}
	var info unix.Stat_t
	err = unix.Fstat(link, &info)
	closeErr := unix.Close(link)
	if err != nil || closeErr != nil || info.Mode&unix.S_IFMT != unix.S_IFLNK {
		return unix.EIO
	}
	restrictedExportStage = "validate"
	err = validatePinnedExport(item, false, uint32(os.Geteuid()), nil)
	if kind == "safe" {
		return err
	}
	if err == nil {
		return unix.EIO
	}
	return nil
}

func TestExportRestricted(t *testing.T) {
	for _, kind := range []string{"safe", "absolute", "parent", "cycle"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			base := filepath.Join(parent, "export")
			if err := os.MkdirAll(filepath.Join(base, "nested"), 0700); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{filepath.Join(base, "record"), filepath.Join(parent, "outside")} {
				if err := os.WriteFile(path, []byte("ordinary export canary"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			target := "nested/up"
			if err := os.Symlink("../record", filepath.Join(base, "nested/up")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(".", filepath.Join(base, "self-directory")); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "absolute":
				target = filepath.Join(parent, "outside")
			case "parent":
				target = "../outside"
			case "cycle":
				target = "link"
			}
			if err := os.Symlink(target, filepath.Join(base, "link")); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/proc/self/exe", "isolation-restricted-export", base, kind)
			command.Env = []string{}
			if observed, err := command.Output(); err != nil {
				stage := string(observed)
				switch stage {
				case "filter", "pin", "inspect", "validate":
				default:
					stage = "unobserved"
				}
				t.Fatalf("acceptance: export walk lost containment under actual openat2 EPERM: stage=%s err=%v", stage, err)
			}
		})
	}
}
