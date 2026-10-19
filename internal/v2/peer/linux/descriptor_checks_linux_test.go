package linux

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func transferDescriptor(t *testing.T) int {
	t.Helper()
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("fixture setup: open descriptor: %v", err)
	}
	return fd
}

func requireDescriptorsClosed(t *testing.T, descriptors []int) {
	t.Helper()
	for _, fd := range descriptors {
		_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if errors.Is(err, unix.EBADF) {
			continue
		}
		if err == nil {
			if closeErr := unix.Close(fd); closeErr != nil {
				t.Errorf("fixture cleanup: close leaked descriptor: %v", closeErr)
			}
			t.Error("fixture check: rejected descriptor is still open")
		} else {
			t.Errorf("fixture check: closed descriptor query must return EBADF, got %v", err)
		}
	}
}

func TestDescriptorFlagsFixture(t *testing.T) {
	for _, mode := range []string{"plain", "cloexec"} {
		t.Run(mode, func(t *testing.T) {
			fd := transferDescriptor(t)
			flags := 0
			if mode == "cloexec" {
				flags = unix.MSG_CMSG_CLOEXEC
			}
			file, err := takeFixtureDescriptor([]byte("f"), unix.UnixRights(fd), flags)
			if err != nil {
				requireDescriptorsClosed(t, []int{fd})
				t.Fatalf("fixture check: valid close-on-exec transfer refused: %v", err)
			}
			if file == nil {
				if err := unix.Close(fd); err != nil {
					t.Errorf("fixture cleanup: close unowned descriptor: %v", err)
				}
				t.Fatal("fixture check: valid transfer returned no descriptor")
			}
			actual, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
			if err != nil {
				t.Errorf("fixture check: returned descriptor flags could not be read: %v", err)
			} else if actual&unix.FD_CLOEXEC == 0 {
				t.Errorf("fixture check: returned descriptor lacks FD_CLOEXEC: flags=%#x", actual)
			}
			closeFixture(t, file.Close)
		})
	}
}

func TestDescriptorRejectFixture(t *testing.T) {
	for _, rule := range []string{"data-trunc", "control-trunc", "unknown-flag", "empty-data",
		"extra-data", "wrong-marker", "missing-control", "extra-control", "extra-fd", "missing-fd", "no-cloexec"} {
		t.Run(rule, func(t *testing.T) {
			data, flags := []byte("f"), unix.MSG_CMSG_CLOEXEC
			var descriptors []int
			var ancillary []byte
			want := ""
			if rule != "missing-control" && rule != "missing-fd" {
				descriptors = append(descriptors, transferDescriptor(t))
				ancillary = unix.UnixRights(descriptors[0])
			}
			switch rule {
			case "data-trunc":
				flags |= unix.MSG_TRUNC
				want = "data truncated"
			case "control-trunc":
				flags |= unix.MSG_CTRUNC
				want = "control truncated"
			case "unknown-flag":
				flags |= unix.MSG_EOR
				want = "unexpected recvmsg flag bits"
			case "empty-data":
				data, want = nil, "data byte count=0"
			case "extra-data":
				data, want = []byte("ff"), "data byte count=2"
			case "wrong-marker":
				data, want = []byte("x"), "data marker="
			case "missing-control":
				want = "control message count=0"
			case "extra-control":
				descriptors = append(descriptors, transferDescriptor(t))
				ancillary = append(ancillary, unix.UnixRights(descriptors[1])...)
				want = "control message count=2"
			case "extra-fd":
				descriptors = append(descriptors, transferDescriptor(t))
				ancillary = unix.UnixRights(descriptors...)
				want = "received descriptor count=2"
			case "missing-fd":
				ancillary, want = unix.UnixRights(), "received descriptor count=0"
			case "no-cloexec":
				if _, err := unix.FcntlInt(uintptr(descriptors[0]), unix.F_SETFD, 0); err != nil {
					t.Fatalf("fixture setup: clear descriptor close-on-exec: %v", err)
				}
				want = "received descriptor lacks FD_CLOEXEC"
			}
			file, err := takeFixtureDescriptor(data, ancillary, flags)
			if file != nil {
				closeFixture(t, file.Close)
				t.Error("fixture check: invalid transfer returned a descriptor")
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("fixture check: want descriptor rejection %q, got %v", want, err)
			}
			requireDescriptorsClosed(t, descriptors)
		})
	}
}
