//go:build linux

package wire

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func endpointFixture(t *testing.T) (*net.UnixListener, *os.File, api.InstalledBinding) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "service.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "socket-fixture")
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	return listener, file, laneBindingFixture()
}

func TestPinnedEndpointTraffic(t *testing.T) {
	listener, source, binding := endpointFixture(t)
	endpoint, err := pinEndpointFD(int(source.Fd()), binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := endpoint.Close(); err != nil {
			t.Error(err)
		}
	})
	if endpoint.file.Fd() == source.Fd() || endpoint.path == listener.Addr().String() {
		t.Fatal("endpoint did not retain its own descriptor-only connection path")
	}
	marker, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			finished <- err
			return
		}
		data := make([]byte, len(marker))
		err = connection.SetDeadline(deadline)
		if err == nil {
			_, err = io.ReadFull(connection, data)
		}
		if err == nil && string(data) != string(marker) {
			err = errors.New("pinned socket received different challenge bytes")
		}
		if err == nil {
			_, err = connection.Write(data)
		}
		finished <- errors.Join(err, connection.Close())
	}()
	connection, err := endpoint.DialContext(ctx, &net.Dialer{})
	if err != nil {
		t.Fatal("descriptor-only endpoint could not connect", err)
	}
	if err := connection.SetDeadline(deadline); err != nil {
		t.Fatal(errors.Join(err, connection.Close()))
	}
	if _, err := connection.Write([]byte(marker)); err != nil {
		t.Fatal(errors.Join(err, connection.Close()))
	}
	actual := make([]byte, len(marker))
	_, readErr := io.ReadFull(connection, actual)
	if err := errors.Join(readErr, connection.Close(), <-finished); err != nil || string(actual) != string(marker) {
		t.Fatal("pinned socket did not carry actual challenge and response bytes", err)
	}
	owned := int(endpoint.file.Fd())
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	var info unix.Stat_t
	if err := unix.Fstat(owned, &info); !errors.Is(err, unix.EBADF) {
		t.Fatal("endpoint close retained its owned socket pin", err)
	}
	if connection, err := endpoint.DialContext(ctx, &net.Dialer{}); err == nil {
		t.Fatal("closed endpoint reconnected", connection.Close())
	}
}

func TestPinnedEndpointGuards(t *testing.T) {
	for _, fault := range []string{"uid", "gid", "mode", "regular", "connected"} {
		t.Run(fault, func(t *testing.T) {
			listener, source, binding := endpointFixture(t)
			fd := int(source.Fd())
			switch fault {
			case "uid":
				binding.MappedServiceUID++
			case "gid":
				binding.MappedServiceGID++
			case "mode":
				if err := os.Chmod(listener.Addr().String(), 0600); err != nil {
					t.Fatal(err)
				}
			case "regular":
				path := filepath.Join(t.TempDir(), "regular-control")
				if err := os.WriteFile(path, []byte("socket inode control"), 0666); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
				regular, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := unix.Close(regular); err != nil {
						t.Error(err)
					}
				})
				fd = regular
			case "connected":
				pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := errors.Join(unix.Close(pair[0]), unix.Close(pair[1])); err != nil {
						t.Error(err)
					}
				})
				fd = pair[0]
				if err := unix.Fchmod(fd, 0666); err != nil {
					t.Fatal("connected socket control could not isolate its descriptor flags", err)
				}
				var info unix.Stat_t
				if unix.Fstat(fd, &info) != nil || !endpointSocket(info, binding) {
					t.Fatal("connected socket control differs beyond its missing O_PATH flag")
				}
			}
			endpoint, err := pinEndpointFD(fd, binding)
			if err == nil {
				t.Fatal("endpoint accepted an unpinned, changed or foreign inode", endpoint.Close())
			}
		})
	}
}
