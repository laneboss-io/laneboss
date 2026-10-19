//go:build linux

package service

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func laneRecoveryFixture(t *testing.T) (*Server, api.LaunchSpec, api.HelperLease, api.InstalledBinding) {
	t.Helper()
	host := fixtureServer(t)
	laneHostFixture(t, host)
	spec, lease := laneSpecFixture(t, host)
	binding, err := wire.LaneEndpointBinding(host.deps.Binding, spec, lease)
	if err != nil {
		t.Fatal(err)
	}
	binding.Socket = filepath.Join(filepath.Dir(host.deps.Binding.Socket), "lanes", string(spec.LaunchID)+".sock")
	return host, spec, lease, binding
}

func recoverySocket(t *testing.T, binding api.InstalledBinding, live bool) os.FileInfo {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: binding.Socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := errors.Join(os.Chmod(binding.Socket, 0666), os.Chown(binding.Socket, int(binding.ServiceUID), int(binding.ServiceGID))); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	if live {
		t.Cleanup(func() {
			if err := listener.Close(); err != nil {
				t.Error(err)
			}
		})
	} else if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(binding.Socket)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestLaneSocketRecovery(t *testing.T) {
	t.Run("stale", func(t *testing.T) {
		host, spec, lease, binding := laneRecoveryFixture(t)
		recoverySocket(t, binding, false)
		if err := host.prepareLaneEndpoint(context.Background(), spec, lease); err != nil {
			t.Fatal("acceptance: stale service-owned lane socket blocked recovery", err)
		}
		connection, err := net.DialTimeout("unix", binding.Socket, time.Second)
		if err != nil {
			t.Fatal("recovered lane socket is not a real listener", err)
		}
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
	})
	for _, name := range []string{"live", "regular", "symlink", "parent-link"} {
		t.Run(name, func(t *testing.T) {
			_, _, _, binding := laneRecoveryFixture(t)
			actual := binding.Socket
			switch name {
			case "live", "parent-link":
				recoverySocket(t, binding, name == "live")
				if name == "parent-link" {
					parent := filepath.Dir(filepath.Dir(actual))
					if err := os.Symlink(parent, filepath.Join(parent, "linked")); err != nil {
						t.Fatal(err)
					}
					binding.Socket = filepath.Join(parent, "linked", "lanes", filepath.Base(actual))
				}
			case "regular":
				if err := os.WriteFile(actual, []byte("retained control"), 0666); err != nil {
					t.Fatal(err)
				}
				if err := errors.Join(os.Chmod(actual, 0666), os.Chown(actual, int(binding.ServiceUID), int(binding.ServiceGID))); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(filepath.Dir(actual), "retained-file")
				if err := os.WriteFile(target, []byte("retained control"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, actual); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(actual)
			if err != nil {
				t.Fatal(err)
			}
			if err := recoverLaneSocket(context.Background(), binding); err == nil {
				t.Fatal("acceptance: lane recovery removed a live, linked or non-socket entry")
			}
			after, err := os.Lstat(actual)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("lane recovery replaced a refused entry", err)
			}
		})
	}
}

func TestLaneSocketReplacement(t *testing.T) {
	for _, name := range []string{"replaced", "owner"} {
		t.Run(name, func(t *testing.T) {
			_, _, _, binding := laneRecoveryFixture(t)
			recoverySocket(t, binding, false)
			parent, err := unix.Open(filepath.Dir(binding.Socket), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(parent)
			var retained unix.Stat_t
			if err := unix.Fstatat(parent, filepath.Base(binding.Socket), &retained, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				t.Fatal(err)
			}
			if name == "replaced" {
				if err := os.Rename(binding.Socket, binding.Socket+".retained"); err != nil {
					t.Fatal(err)
				}
				recoverySocket(t, binding, false)
			} else {
				// The real inode has a different UID from the asserted service.
				binding.ServiceUID++
			}
			before, err := os.Lstat(binding.Socket)
			if err != nil {
				t.Fatal(err)
			}
			if err := unlinkStaleLaneSocket(parent, filepath.Base(binding.Socket), retained, binding); err == nil {
				t.Fatal("acceptance: stale recovery unlinked a replaced or foreign inode")
			}
			after, err := os.Lstat(binding.Socket)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("refused stale recovery lost the current entry", err)
			}
		})
	}
}
