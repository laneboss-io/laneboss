//go:build linux

package admin

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestHelperOpenat2Policy(t *testing.T) {
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := helperUnitFixture(directory)
	if err != nil {
		t.Fatal(err)
	}
	section := ""
	settings := map[string][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if section != "[Service]" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if found {
			settings[strings.TrimSpace(key)] = append(settings[strings.TrimSpace(key)], strings.TrimSpace(value))
		}
	}
	values := settings["RestrictSUIDSGID"]
	if len(values) != 1 {
		t.Fatal("helper unit must declare one SUID/SGID restriction")
	}
	switch strings.ToLower(values[0]) {
	case "yes", "true", "on", "1":
	default:
		t.Fatal("acceptance: helper unit lost its SUID/SGID restriction")
	}
	for _, property := range []string{"NoNewPrivileges", "ProtectSystem", "ProtectHome", "ProtectKernelTunables"} {
		values := settings[property]
		if len(values) != 1 || property == "ProtectSystem" && values[0] != "strict" || property != "ProtectSystem" && values[0] != "yes" {
			t.Fatal("helper native-open compatibility changed another confinement policy")
		}
	}
}

func TestNativeMountPin(t *testing.T) {
	testNativeMountPins(t, unix.Openat2)
}

func TestMountFallback(t *testing.T) {
	for _, trigger := range []struct {
		name  string
		cause error
	}{{"eperm", unix.EPERM}, {"enosys", unix.ENOSYS}} {
		t.Run(trigger.name, func(t *testing.T) {
			// Force only the first syscall result. The component walk, descriptor
			// opens and final native metadata checks remain the production code.
			testNativeMountPins(t, func(int, string, *unix.OpenHow) (int, error) {
				return -1, &os.SyscallError{Syscall: "openat2", Err: trigger.cause}
			})
		})
	}
}

func testNativeMountPins(t *testing.T, openat2 nativeMountOpenat2) {
	t.Helper()
	for _, name := range []string{"regular", "directory", "missing", "middle-link", "leaf-link", "magic-link", "wrong-owner", "wrong-group", "writable", "wrong-type"} {
		t.Run(name, func(t *testing.T) {
			root := privateTestDir(t)
			source := filepath.Join(root, "runtime", "nested")
			if err := os.MkdirAll(source, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(source, "artifact")
			content, err := randomID("mount-bytes-")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			path := file
			directory := false
			uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
			switch name {
			case "directory":
				path, directory = source, true
			case "missing":
				path = filepath.Join(root, "absent")
			case "middle-link":
				link := filepath.Join(root, "alias")
				if err := os.Symlink(source, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "artifact")
			case "leaf-link":
				path = filepath.Join(root, "alias")
				if err := os.Symlink(file, path); err != nil {
					t.Fatal(err)
				}
			case "magic-link":
				held, err := os.Open(file)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := held.Close(); err != nil {
						t.Error(err)
					}
				}()
				path = dataFD(held)
			case "wrong-owner":
				uid++
			case "wrong-group":
				gid++
			case "writable":
				if err := os.Chmod(file, 0620); err != nil {
					t.Fatal(err)
				}
			case "wrong-type":
				directory = true
			}
			calls := 0
			tracked := func(dirfd int, name string, how *unix.OpenHow) (int, error) {
				calls++
				if dirfd != unix.AT_FDCWD || name != path || how.Flags != unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW || how.Resolve != unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS || how.Mode != 0 {
					t.Fatal("native mount changed its strict initial open")
				}
				return openat2(dirfd, name, how)
			}
			allowed := captureAllowed(t)
			mount, err := pinNativeMountWithOpenat2(path, "/runtime/component", directory, false, false, uid, gid, tracked)
			if calls != 1 {
				t.Fatal("native mount did not reach the controlled initial syscall")
			}
			if name == "wrong-owner" || name == "wrong-group" || name == "writable" {
				// Owner R181-R192: owner, group and mode pinning is allowed and logged; the actual source still pins.
				if err != nil || mount == nil || !slices.Equal(allowed(), []string{"native_mount_owner"}) {
					t.Fatal("native mount owner pin was not allowed and logged", err, allowed())
				}
				if err := mount.file.Close(); err != nil {
					t.Error(err)
				}
				return
			}
			if name != "regular" && name != "directory" {
				var typed *api.Error
				if err == nil || mount != nil || !errors.As(err, &typed) || (typed.Code != api.CodeContainmentUnknown && typed.Code != api.CodeIntegrity) {
					if mount != nil {
						if err := mount.file.Close(); err != nil {
							t.Error(err)
						}
					}
					t.Fatal("acceptance: native mount pin admitted an unproved source", err)
				}
				return
			}
			if err != nil || mount == nil || len(allowed()) != 0 {
				t.Fatal("native mount pin could not open the real protected source", err, allowed())
			}
			defer func() {
				if err := mount.file.Close(); err != nil {
					t.Error(err)
				}
			}()
			var held, named unix.Stat_t
			if unix.Fstat(int(mount.file.Fd()), &held) != nil || unix.Lstat(path, &named) != nil || held.Dev != named.Dev || held.Ino != named.Ino || held.Uid != uid || held.Gid != gid || mount.directory != directory {
				t.Fatal("native mount pin did not retain the actual inode and metadata")
			}
			flags, err := unix.FcntlInt(mount.file.Fd(), unix.F_GETFL, 0)
			fdFlags, fdErr := unix.FcntlInt(mount.file.Fd(), unix.F_GETFD, 0)
			if err != nil || fdErr != nil || flags&unix.O_PATH == 0 || fdFlags&unix.FD_CLOEXEC == 0 {
				t.Fatal("native source lost its O_PATH or close-on-exec pin")
			}
		})
	}
}

func TestMountFallbackParts(t *testing.T) {
	container := privateTestDir(t)
	root := filepath.Join(container, "trusted")
	if err := os.MkdirAll(filepath.Join(root, "runtime", "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runtime", "nested", "artifact"), []byte("inside"), 0600); err != nil {
		t.Fatal(err)
	}
	// A real sibling is the escape canary if a '..' component is admitted.
	if err := os.WriteFile(filepath.Join(container, "outside-artifact"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	held, err := unix.Open(root, unix.O_PATH|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Close(held); err != nil {
			t.Error(err)
		}
	}()
	for _, entry := range []struct{ name, path string }{
		{"nested", "runtime/nested/artifact"}, {"parent", "../outside-artifact"}, {"middle-parent", "runtime/../nested/artifact"},
		{"absolute", "/runtime/nested/artifact"}, {"empty", ""}, {"empty-middle", "runtime//nested/artifact"},
		{"empty-leaf", "runtime/nested/"}, {"dot", "runtime/./nested/artifact"}, {"nul", "runtime/\x00/artifact"},
	} {
		t.Run(entry.name, func(t *testing.T) {
			fd, err := walkNativeMountAt(held, entry.path)
			if fd >= 0 {
				defer func() {
					if err := unix.Close(fd); err != nil {
						t.Error(err)
					}
				}()
			}
			if entry.name != "nested" {
				if fd >= 0 || !errors.Is(err, unix.EINVAL) {
					t.Fatal("acceptance: fallback admitted an invalid or escaping component", err)
				}
				return
			}
			var actual, expected unix.Stat_t
			if err != nil || fd < 0 || unix.Fstat(fd, &actual) != nil || unix.Lstat(filepath.Join(root, entry.path), &expected) != nil || actual.Dev != expected.Dev || actual.Ino != expected.Ino {
				t.Fatal("fallback did not retain the nested source beneath its trusted root", err)
			}
		})
	}
	var original unix.Stat_t
	if err := unix.Fstat(held, &original); err != nil {
		t.Fatal("fallback closed its caller's trusted root", err)
	}
}

func TestMountFallbackEligibility(t *testing.T) {
	root := privateTestDir(t)
	source := filepath.Join(root, "artifact")
	if err := os.WriteFile(source, []byte("existing source"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, cause := range []error{unix.EACCES, unix.ENOENT, unix.ELOOP, unix.EINVAL, unix.ENOTDIR, unix.EIO} {
		t.Run(cause.Error(), func(t *testing.T) {
			original := &os.SyscallError{Syscall: "openat2", Err: cause}
			calls := 0
			fd, err := openNativeMountSource(source, func(int, string, *unix.OpenHow) (int, error) { calls++; return -1, original })
			if fd >= 0 {
				if closeErr := unix.Close(fd); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if fd >= 0 || err != original || calls != 1 {
				t.Fatal("acceptance: fallback bypassed an unrelated initial refusal", err)
			}
		})
	}
}

func TestNativeMountPinDiagnostic(t *testing.T) {
	for _, entry := range []struct {
		cause    error
		category string
	}{
		{unix.EPERM, "openat2 denied"}, {unix.EACCES, "source access denied"}, {unix.ENOENT, "source missing"},
		{unix.ELOOP, "symbolic or magic link refused"}, {unix.ENOSYS, "openat2 unavailable"},
		{unix.ENOTDIR, "source component is not a directory"}, {unix.EINVAL, "openat2 flags unsupported"}, {unix.EIO, "native open failed"},
		{&nativeMountWalkError{cause: unix.EPERM}, "component walk: openat denied"},
		{&nativeMountWalkError{cause: unix.ENOSYS}, "component walk: openat unavailable"},
		{&nativeMountWalkError{cause: unix.EINVAL}, "component walk: source components invalid"},
		{&nativeMountWalkError{cause: unix.ENOENT}, "component walk: source missing"},
	} {
		t.Run(entry.category, func(t *testing.T) {
			private, err := randomID("private-source-")
			if err != nil {
				t.Fatal(err)
			}
			wrapped := &os.PathError{Op: "open", Path: "/" + string(private), Err: entry.cause}
			var typed *api.Error
			if err := nativeMountPinError(wrapped); !errors.As(err, &typed) || typed.Owner != "lb-v2-admin" || typed.Code != api.CodeContainmentUnknown || typed.Message != "cannot pin native mount source without links ("+entry.category+")" {
				t.Fatal("native mount refusal lost its safe syscall category", err)
			}
			if strings.Contains(typed.Message, string(private)) || strings.Contains(typed.Instead, string(private)) {
				t.Fatal("native mount diagnostic disclosed a private source")
			}
		})
	}
}
