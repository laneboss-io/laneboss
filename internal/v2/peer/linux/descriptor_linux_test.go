package linux

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// takeFixtureDescriptor takes ownership of all delivered SCM_RIGHTS descriptors.
// Failure closes every parsed descriptor. Go's Linux ReadMsgUnix requests
// MSG_CMSG_CLOEXEC; that informational result bit is not truncation. The
// descriptor's real FD_CLOEXEC state must be verified before it can be used.
func takeFixtureDescriptor(data, ancillary []byte, flags int) (file *os.File, result error) {
	messages, err := unix.ParseSocketControlMessage(ancillary)
	if err != nil {
		return nil, fmt.Errorf("parse control messages: %w", err)
	}
	var descriptors []int
	defer func() {
		if result == nil {
			return
		}
		closed := make(map[int]bool)
		for _, fd := range descriptors {
			if !closed[fd] {
				closed[fd] = true
				if err := unix.Close(fd); err != nil {
					result = errors.Join(result, fmt.Errorf("close rejected descriptor: %w", err))
				}
			}
		}
	}()
	for index := range messages {
		message := &messages[index]
		if message.Header.Level != unix.SOL_SOCKET || message.Header.Type != unix.SCM_RIGHTS {
			continue
		}
		if len(message.Data)%4 != 0 {
			return nil, fmt.Errorf("rights payload has %d bytes, want whole descriptors", len(message.Data))
		}
		rights, err := unix.ParseUnixRights(message)
		if err != nil {
			return nil, fmt.Errorf("parse rights payload: %w", err)
		}
		descriptors = append(descriptors, rights...)
	}
	if flags&unix.MSG_TRUNC != 0 {
		return nil, fmt.Errorf("data truncated: recvmsg flags=%#x", flags)
	}
	if flags&unix.MSG_CTRUNC != 0 {
		return nil, fmt.Errorf("control truncated: recvmsg flags=%#x", flags)
	}
	if unexpected := flags &^ unix.MSG_CMSG_CLOEXEC; unexpected != 0 {
		return nil, fmt.Errorf("unexpected recvmsg flag bits=%#x", unexpected)
	}
	if len(data) != 1 {
		return nil, fmt.Errorf("data byte count=%d, want 1", len(data))
	}
	if data[0] != 'f' {
		return nil, fmt.Errorf("data marker=%#x, want f", data[0])
	}
	if len(messages) != 1 {
		return nil, fmt.Errorf("control message count=%d, want 1", len(messages))
	}
	if messages[0].Header.Level != unix.SOL_SOCKET || messages[0].Header.Type != unix.SCM_RIGHTS {
		return nil, fmt.Errorf("control message level=%d type=%d, want SOL_SOCKET/SCM_RIGHTS",
			messages[0].Header.Level, messages[0].Header.Type)
	}
	if len(descriptors) != 1 {
		return nil, fmt.Errorf("received descriptor count=%d, want 1", len(descriptors))
	}
	fdFlags, err := unix.FcntlInt(uintptr(descriptors[0]), unix.F_GETFD, 0)
	if err != nil {
		return nil, fmt.Errorf("read received descriptor flags: %w", err)
	}
	if fdFlags&unix.FD_CLOEXEC == 0 {
		return nil, fmt.Errorf("received descriptor lacks FD_CLOEXEC: fd flags=%#x", fdFlags)
	}
	return os.NewFile(uintptr(descriptors[0]), "passed-fixture"), nil
}
