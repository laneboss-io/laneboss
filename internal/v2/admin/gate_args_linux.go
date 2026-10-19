//go:build linux

package admin

import (
	"os"
	"strconv"
)

// ExtraFiles supplies the exact descriptor grammar to exec. Bubblewrap 0.9.0
// has no --preserve-fds option. The bootstrap verifies its inherited sealed
// input, release pipe and control peer, then CloseRange(CLOEXEC) protects every
// remaining descriptor before vendor exec; no privilege property is removed.
func nativeGateArgs(config, mode string, controls []*os.File, mounts []*nativeMount, unshareNetwork bool) ([]string, []*os.File) {
	args := []string{"--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
		"--cap-drop", "ALL", "--clearenv", "--setenv", "GOMAXPROCS", "1",
		"--proc", "/proc", "--dev", "/dev", "--dir", "/work", "--dir", "/home", "--dir", "/run", "--dir", "/run/laneboss", "--dir", "/runtime", "--dir", "/job",
		"--perms", "0700", "--tmpfs", "/tmp", "--perms", "0700", "--tmpfs", "/run/lane", "--perms", "0700", "--tmpfs", "/dev/shm"}
	files := append([]*os.File{}, controls...)
	if unshareNetwork {
		args = append(args, "--unshare-net")
	}
	for _, mount := range mounts {
		if mount.target == privateResolver && mount.resolver {
			args = append(args, resolverMountArgs(3+len(files))...)
			files = append(files, mount.file)
			continue
		}
		if mount.socket || mount.sealed {
			args = append(args, "--symlink", "/proc/self/fd/"+strconv.Itoa(3+len(files)), mount.target)
			files = append(files, mount.file)
			continue
		}
		flag := "--ro-bind-fd"
		if mount.writable {
			flag = "--bind-fd"
		}
		args = append(args, flag, strconv.Itoa(3+len(files)), mount.target)
		files = append(files, mount.file)
	}
	// The fixed bootstrap's TSYNC seccomp denies nested user namespaces.
	// bwrap's sysctl-based disabling cannot run under ProtectKernelTunables.
	args = append(args, "--remount-ro", "/proc", "--remount-ro", "/", "--", fixedBootstrapPath, FixedBootstrapEntry, mode, "--config", config)
	return args, files
}
