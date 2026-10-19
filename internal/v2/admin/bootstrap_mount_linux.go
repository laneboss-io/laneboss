//go:build linux

package admin

import "strings"

// Bind errors do not always spell out --ro-bind. Retain only the requested
// destination/mode, privately, to disambiguate the failing operation. Never
// infer an operation from a word found inside an arbitrary source path.
type bootstrapBindRequest struct {
	target   string
	readonly bool
}

func bootstrapBindRequests(args []string) []bootstrapBindRequest {
	var result []bootstrapBindRequest
	for index := 1; index < len(args); index++ {
		switch args[index] {
		case "--":
			return result
		case "--bind", "--ro-bind", "--bind-fd", "--ro-bind-fd":
			if index+2 >= len(args) {
				return nil
			}
			result = append(result, bootstrapBindRequest{target: args[index+2], readonly: args[index] == "--ro-bind" || args[index] == "--ro-bind-fd"})
			index += 2
		case "--symlink":
			// A private operand may itself look like an option or delimiter.
			index += 2
		case "--proc", "--dev", "--dir", "--perms", "--tmpfs", "--cap-drop", "--remount-ro":
			index++
		}
	}
	return result
}

func (s *bootstrapStderr) diagnosticFacts() string {
	if s == nil {
		return "bwrap_stderr=unavailable; bwrap_mount=unavailable; bwrap_errno=unavailable"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, errno := bwrapMountFacts(s.prefix, s.binds)
	return "bwrap_stderr=" + classifyBwrapStderr(s.prefix) + "; bwrap_mount=" + operation + "; bwrap_errno=" + errno
}

func bwrapMountFacts(data []byte, binds []bootstrapBindRequest) (string, string) {
	for _, line := range strings.Split(string(data), "\n") {
		category := classifyBwrapStderr([]byte(line))
		switch category {
		case "none", "other":
			continue
		case "mount_failed", "bind_mount_failed", "mount_propagation_failed":
			// Parse the same first recognized setup line as the coarse fact.
			// Later/vendor stderr cannot replace an earlier setup observation.
			message, text, found := cutBwrapErrno(line)
			errno := "other"
			if found {
				errno = bwrapErrnoName(text)
			}
			return bwrapMountOperation(message, binds), errno
		default:
			return "none", "none"
		}
	}
	return "none", "none"
}

func cutBwrapErrno(line string) (string, string, bool) {
	index := strings.LastIndex(line, ": ")
	if index <= len("bwrap:") {
		return line, "", false
	}
	return line[:index], line[index+2:], true
}

func bwrapMountOperation(message string, binds []bootstrapBindRequest) string {
	for _, prefix := range []string{"bwrap: Can't mount ", "bwrap: Failed to mount ", "bwrap: mount "} {
		if operand, ok := strings.CutPrefix(message, prefix); ok {
			switch {
			case strings.HasPrefix(operand, "proc on "):
				return "proc"
			case strings.HasPrefix(operand, "tmpfs on "):
				return "tmpfs"
			case strings.HasPrefix(operand, "devpts on "):
				return "dev"
			case strings.HasPrefix(operand, "mqueue on "):
				return "mqueue"
			}
		}
	}
	if strings.HasPrefix(message, "bwrap: Can't remount ") ||
		strings.HasPrefix(message, "bwrap: Can't make / ") || strings.HasPrefix(message, "bwrap: Failed to make / ") {
		return "remount"
	}
	if strings.HasPrefix(message, "bwrap: Can't bind mount ") || strings.HasPrefix(message, "bwrap: Failed to bind mount ") {
		message = strings.TrimSuffix(message, ": Unable to mount source on destination")
		operation := ""
		for _, bind := range binds {
			if !strings.HasPrefix(bind.target, "/") || strings.ContainsAny(bind.target, "\x00\r\n") ||
				!strings.HasSuffix(message, " on "+bind.target) && !strings.HasSuffix(message, " on /newroot"+bind.target) {
				continue
			}
			current := "bind"
			if bind.readonly {
				current = "ro-bind"
			}
			if operation != "" && operation != current {
				return "other"
			}
			operation = current
		}
		if operation != "" {
			return operation
		}
		// The stderr still identifies a bind syscall, but its requested
		// read-only mode is unknown without an unambiguous argv match.
		return "bind"
	}
	return "other"
}

// The native child starts with an empty environment, so libc uses its C
// messages. Unknown/localized/truncated text remains other, never raw text.
func bwrapErrnoName(text string) string {
	switch text {
	case "Operation not permitted":
		return "EPERM"
	case "Permission denied":
		return "EACCES"
	case "Read-only file system":
		return "EROFS"
	case "Invalid argument":
		return "EINVAL"
	case "No such file or directory":
		return "ENOENT"
	case "Not a directory":
		return "ENOTDIR"
	case "No such device":
		return "ENODEV"
	case "Device or resource busy":
		return "EBUSY"
	case "Cannot allocate memory":
		return "ENOMEM"
	case "No space left on device":
		return "ENOSPC"
	case "Too many levels of symbolic links":
		return "ELOOP"
	case "Function not implemented":
		return "ENOSYS"
	case "Operation not supported":
		return "EOPNOTSUPP"
	case "Input/output error":
		return "EIO"
	case "Bad file descriptor":
		return "EBADF"
	case "Too many open files":
		return "EMFILE"
	case "Too many open files in system":
		return "ENFILE"
	default:
		return "other"
	}
}
