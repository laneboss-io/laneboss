//go:build linux

package admin

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

const bootstrapStderrLimit = 8192

func attachBootstrapStderr(cmd *exec.Cmd, destination *os.File) (*bootstrapStderr, error) {
	if destination == nil {
		return nil, failure(api.CodePrerequisite, "bootstrap stderr requires its owned capture descriptor")
	}
	fd, err := unix.FcntlInt(destination.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, failure(api.CodeIntegrity, "cannot retain bootstrap stderr capture descriptor")
	}
	owned := os.NewFile(uintptr(fd), "owned-bootstrap-stderr")
	flags, err := unix.FcntlInt(owned.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE == unix.O_RDONLY {
		if closeErr := owned.Close(); closeErr != nil {
			return nil, failure(api.CodeIntegrity, "cannot close refused stderr capture descriptor")
		}
		return nil, failure(api.CodeIntegrity, "bootstrap stderr capture descriptor is not writable")
	}
	observer := &bootstrapStderr{destination: owned, owned: owned}
	observer.binds = bootstrapBindRequests(cmd.Args)
	cmd.Stderr = observer
	// The full producer lifetime owns stderr. A timer must not truncate a
	// descendant's final audit bytes after the primary process exits.
	cmd.WaitDelay = 0
	return observer, nil
}

// Forward exact bytes to the existing private stderr owner. Keep a bounded
// bootstrap prefix and a separate bounded first line through the worker's
// lifetime. Only closed classifications, never these bytes, enter diagnostics.
type bootstrapStderr struct {
	mu          sync.Mutex
	destination io.Writer
	owned       *os.File
	prefix      []byte
	binds       []bootstrapBindRequest
	frozen      bool
	firstLine   []byte
	lineDone    bool
}

// Only the wait owner calls close after cmd.Wait has drained all stderr.
// Start failures retain ownership in the starter until their wait completes.
func (s *bootstrapStderr) close() error {
	s.mu.Lock()
	owned := s.owned
	s.owned = nil
	s.mu.Unlock()
	if owned != nil {
		return owned.Close()
	}
	return nil
}

func (s *bootstrapStderr) Write(data []byte) (int, error) {
	s.mu.Lock()
	if !s.lineDone {
		line, _, ended := bytes.Cut(data, []byte{'\n'})
		count := min(len(line), bootstrapStderrLimit-len(s.firstLine))
		s.firstLine = append(s.firstLine, line[:count]...)
		s.lineDone = ended || len(s.firstLine) == bootstrapStderrLimit
	}
	if !s.frozen && len(s.prefix) < bootstrapStderrLimit {
		count := min(len(data), bootstrapStderrLimit-len(s.prefix))
		s.prefix = append(s.prefix, data[:count]...)
	}
	s.mu.Unlock()
	return s.destination.Write(data)
}

func (s *bootstrapStderr) freeze() {
	s.mu.Lock()
	s.frozen = true
	s.mu.Unlock()
}

func (s *bootstrapStderr) fact() string {
	if s == nil {
		return "unavailable"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return classifyBwrapStderr(s.prefix)
}

func classifyBwrapStderr(data []byte) string {
	if len(data) == 0 {
		return "none"
	}
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "bwrap: Creating new namespace failed:") &&
			(strings.HasSuffix(line, "Permission denied") || strings.HasSuffix(line, "Operation not permitted")),
			strings.HasPrefix(line, "bwrap: No permissions to create new namespace"):
			return "namespace_denied"
		case strings.HasPrefix(line, "bwrap: Creating new namespace failed:"), strings.HasPrefix(line, "bwrap: Can't create user namespace"):
			return "namespace_setup_failed"
		case strings.HasPrefix(line, "bwrap: Unknown option "), strings.HasPrefix(line, "bwrap: Unknown option:"):
			return "option_unsupported"
		case strings.HasPrefix(line, "bwrap: --disable-userns requires"), strings.HasPrefix(line, "bwrap: --assert-userns-disabled requires"),
			strings.HasPrefix(line, "bwrap: Failed to disable user namespaces"), strings.HasPrefix(line, "bwrap: Can't disable user namespaces"):
			return "userns_policy_failed"
		case strings.HasPrefix(line, "bwrap: Can't find source path "), strings.HasPrefix(line, "bwrap: Can't resolve source path "),
			strings.HasPrefix(line, "bwrap: Can't stat "):
			return "mount_source_unavailable"
		case strings.HasPrefix(line, "bwrap: Can't bind mount "), strings.HasPrefix(line, "bwrap: Failed to bind mount "):
			return "bind_mount_failed"
		case strings.HasPrefix(line, "bwrap: Can't mkdir "), strings.HasPrefix(line, "bwrap: Can't create directory "),
			strings.HasPrefix(line, "bwrap: Can't create file at "), strings.HasPrefix(line, "bwrap: Creating directory "):
			return "destination_create_failed"
		case strings.HasPrefix(line, "bwrap: Can't make / "), strings.HasPrefix(line, "bwrap: Failed to make / "),
			strings.HasPrefix(line, "bwrap: Can't remount "):
			return "mount_propagation_failed"
		case strings.HasPrefix(line, "bwrap: pivot_root:"), strings.HasPrefix(line, "bwrap: Can't pivot_root"), strings.HasPrefix(line, "bwrap: pivot_root "):
			return "root_switch_failed"
		case strings.HasPrefix(line, "bwrap: Can't chdir to "), strings.HasPrefix(line, "bwrap: chdir "):
			return "cwd_failed"
		case strings.HasPrefix(line, "bwrap: capset failed"), strings.HasPrefix(line, "bwrap: capset:"), strings.HasPrefix(line, "bwrap: Can't set capabilities"):
			return "capability_setup_failed"
		case strings.HasPrefix(line, "bwrap: prctl(PR_SET_PDEATHSIG)"), strings.HasPrefix(line, "bwrap: Can't set parent death signal"):
			return "parent_death_setup_failed"
		case strings.HasPrefix(line, "bwrap: prctl(PR_SET_NO_NEW_PRIVS)"), strings.HasPrefix(line, "bwrap: Can't set no_new_privs"):
			return "no_new_privileges_failed"
		case strings.HasPrefix(line, "bwrap: Failed to sync with child"), strings.HasPrefix(line, "bwrap: Can't read from eventfd"),
			strings.HasPrefix(line, "bwrap: Can't write to eventfd"), strings.HasPrefix(line, "bwrap: read from eventfd"):
			return "child_sync_failed"
		case strings.HasPrefix(line, "bwrap: Can't set up seccomp"), strings.HasPrefix(line, "bwrap: prctl(PR_SET_SECCOMP)"),
			strings.HasPrefix(line, "bwrap: Can't load seccomp"), strings.HasPrefix(line, "bwrap: seccomp:"):
			return "seccomp_setup_failed"
		case strings.HasPrefix(line, "bwrap: Failed to fork"), strings.HasPrefix(line, "bwrap: fork:"),
			strings.HasPrefix(line, "bwrap: Can't fork"), strings.HasPrefix(line, "bwrap: Failed to clone"):
			return "process_create_failed"
		case strings.HasPrefix(line, "bwrap: out of memory"), strings.HasPrefix(line, "bwrap: Out of memory"),
			strings.HasPrefix(line, "bwrap: malloc:"), strings.HasPrefix(line, "bwrap: realloc:"):
			return "allocation_failed"
		case strings.HasPrefix(line, "runtime: failed to create new OS thread"):
			return "runtime_thread_failed"
		case strings.HasPrefix(line, "fatal error: runtime: out of memory"), strings.HasPrefix(line, "runtime: cannot allocate memory"), strings.HasPrefix(line, "runtime: out of memory"):
			return "runtime_memory_failed"
		case strings.HasPrefix(line, "bwrap: Can't open "):
			return "descriptor_or_path_unavailable"
		case strings.HasPrefix(line, "bwrap: Can't mount "), strings.HasPrefix(line, "bwrap: mount "), strings.HasPrefix(line, "bwrap: Failed to mount "):
			return "mount_failed"
		case strings.HasPrefix(line, "bwrap: execvp "), strings.HasPrefix(line, "bwrap: execvpe "):
			return "exec_failed"
		case strings.HasPrefix(line, "bwrap: setting up uid map:"), strings.HasPrefix(line, "bwrap: setting up gid map:"):
			return "identity_map_failed"
		}
	}
	return "other"
}
