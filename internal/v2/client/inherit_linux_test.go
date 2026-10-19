//go:build linux

package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// This is solely a subprocess fixture in the test binary. It proves actual
// os/exec inheritance and byte traffic, not a service/job principal.
func init() {
	if len(os.Args) != 6 || os.Args[1] != "client-lane-inherit-fixture" {
		return
	}
	marker := []byte(os.Args[2])
	const required = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	seals, err := unix.FcntlInt(6, unix.F_GET_SEALS, 0)
	data := make([]byte, len(marker))
	n, readErr := unix.Pread(6, data, 0)
	if err != nil || seals&required != required || readErr != nil || n != len(marker) || string(data) != string(marker) {
		os.Exit(81)
	}
	device, devErr := strconv.ParseUint(os.Args[3], 10, 64)
	inode, inoErr := strconv.ParseUint(os.Args[4], 10, 64)
	foreignFD, fdErr := strconv.Atoi(os.Args[5])
	if devErr != nil || inoErr != nil || fdErr != nil {
		os.Exit(82)
	}
	var foreign unix.Stat_t
	if unix.Fstat(foreignFD, &foreign) == nil && uint64(foreign.Dev) == device && foreign.Ino == inode {
		os.Exit(83)
	}
	connection, err := net.DialTimeout("unix", "/proc/self/fd/7", 3*time.Second)
	if err != nil {
		os.Exit(84)
	}
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		os.Exit(85)
	}
	if _, err := connection.Write(marker); err != nil {
		os.Exit(86)
	}
	n, err = io.ReadFull(connection, data)
	if err != nil || n != len(marker) || string(data) != string(marker) || connection.Close() != nil {
		os.Exit(87)
	}
	os.Exit(0)
}

func TestLaneCommandInheritance(t *testing.T) {
	for _, mode := range []string{"omitted-control", "retained"} {
		t.Run(mode, func(t *testing.T) {
			marker, err := NewRequestID()
			if err != nil {
				t.Fatal(err)
			}
			fd, err := unix.MemfdCreate("lane-command-fixture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
			if err != nil {
				t.Fatal(err)
			}
			binding := os.NewFile(uintptr(fd), "command-binding")
			t.Cleanup(func() {
				if err := binding.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
					t.Error(err)
				}
			})
			if n, err := binding.Write([]byte(marker)); err != nil || n != len(marker) {
				t.Fatal("could not retain actual child input bytes", err)
			}
			if err := binding.Chmod(0444); err != nil {
				t.Fatal(err)
			}
			const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
			if _, err := unix.FcntlInt(binding.Fd(), unix.F_ADD_SEALS, seals); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "socket")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Error(err)
				}
			})
			if err := os.Chmod(path, 0666); err != nil {
				t.Fatal(err)
			}
			socketFD, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			socket := os.NewFile(uintptr(socketFD), "command-socket")
			t.Cleanup(func() {
				if err := socket.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
					t.Error(err)
				}
			})
			foreign, err := os.CreateTemp(t.TempDir(), "not-forwarded")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := foreign.Close(); err != nil {
					t.Error(err)
				}
			})
			foreignFD, err := unix.FcntlInt(foreign.Fd(), unix.F_DUPFD_CLOEXEC, 64)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := unix.FcntlInt(uintptr(foreignFD), unix.F_SETFD, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := unix.Close(foreignFD); err != nil {
					t.Error(err)
				}
			})
			var foreignInfo unix.Stat_t
			if err := unix.Fstat(int(foreign.Fd()), &foreignInfo); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				connection, err := listener.AcceptUnix()
				if err != nil {
					finished <- err
					return
				}
				data := make([]byte, len(marker))
				err = connection.SetDeadline(time.Now().Add(3 * time.Second))
				if err == nil {
					_, err = io.ReadFull(connection, data)
				}
				if err == nil && string(data) != string(marker) {
					err = errors.New("child sent different inherited bytes")
				}
				if err == nil {
					_, err = connection.Write(data)
				}
				finished <- errors.Join(err, connection.Close())
			}()
			command := exec.CommandContext(ctx, "/proc/self/exe", "client-lane-inherit-fixture", string(marker),
				strconv.FormatUint(uint64(foreignInfo.Dev), 10), strconv.FormatUint(foreignInfo.Ino, 10), strconv.Itoa(foreignFD))
			var closeErr error
			if mode == "retained" {
				owned, err := attachLaneDescriptors(command, []wire.InheritedFile{{FD: 6, File: binding}, {FD: 7, File: socket}})
				if err != nil {
					t.Fatal(err)
				}
				err = command.Start()
				closeErr = owned.Close()
				if err == nil {
					err = command.Wait()
				}
				if err != nil || closeErr != nil {
					t.Fatal("child lost exact inherited descriptor numbers or byte traffic", errors.Join(err, closeErr))
				}
			} else {
				err = command.Run()
				closeErr = errors.Join(binding.Close(), socket.Close())
				var exited *exec.ExitError
				if !errors.As(err, &exited) || exited.ExitCode() != 81 || closeErr != nil {
					t.Fatal("omitted os/exec control did not reach missing sealed input refusal", errors.Join(err, closeErr))
				}
			}
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			serverErr := <-finished
			if mode == "retained" && serverErr != nil || mode == "omitted-control" && !errors.Is(serverErr, net.ErrClosed) {
				t.Fatal("child descriptor control did not measure its expected socket traffic", serverErr)
			}
		})
	}
}
