//go:build linux

package admin

import (
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func nativePair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	connections := make([]*net.UnixConn, 0, 2)
	for _, fd := range fds {
		file := os.NewFile(uintptr(fd), "helper-test-socket")
		connection, err := net.FileConn(file)
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			t.Fatal("native socket conversion failed")
		}
		unixConnection, ok := connection.(*net.UnixConn)
		if !ok {
			connection.Close()
			t.Fatal("socket is not Unix")
		}
		t.Cleanup(func() { unixConnection.Close() })
		if err := unixConnection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		connections = append(connections, unixConnection)
	}
	return connections[0], connections[1]
}

func nativePeer(t *testing.T, connection *net.UnixConn) *pinnedPeer {
	t.Helper()
	peer, err := pinPeer(connection, uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closePeer(peer) })
	return peer
}

func TestNativeFrames(t *testing.T) {
	for _, mode := range []string{"ordinary", "rights", "oversize", "wrong-peer"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer := nativePair(t)
			peer := nativePeer(t, reader)
			if mode == "wrong-peer" {
				_, err := pinPeer(reader, uint32(os.Getuid())+1, uint32(os.Getgid()))
				requireCode(t, err, api.CodeForbidden)
				return
			}
			data, err := frame([]byte("{}"))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "oversize" {
				data = make([]byte, 4)
				binary.BigEndian.PutUint32(data, api.MaxFrameBytes+1)
			}
			if mode == "rights" {
				file, err := os.Open("/dev/null")
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if _, _, err := writer.WriteMsgUnix(data, unix.UnixRights(int(file.Fd())), nil); err != nil {
					t.Fatal(err)
				}
			} else if _, err := writer.Write(data); err != nil {
				t.Fatal(err)
			}
			actual, err := readUnixFrame(reader, peer)
			switch mode {
			case "ordinary":
				if err != nil || string(actual) != "{}" {
					t.Fatalf("actual native frame differs: %v", err)
				}
			case "rights":
				requireCode(t, err, api.CodeForbidden)
			case "oversize":
				requireCode(t, err, api.CodeInvalid)
			}
		})
	}
}

func TestNativeFragments(t *testing.T) {
	for _, fragment := range []string{"header", "body"} {
		t.Run(fragment, func(t *testing.T) {
			reader, writer := nativePair(t)
			peer := nativePeer(t, reader)
			data, err := frame([]byte("{}"))
			if err != nil {
				t.Fatal(err)
			}
			prefix, suffix := data[:4], "{}"
			if fragment == "header" {
				prefix, suffix = data[:2], `\000\002{}`
			}
			if _, err := writer.Write(prefix); err != nil {
				t.Fatal(err)
			}
			// Pass an actual duplicate of the connected socket as stdout. Using
			// a Go copying goroutine here would falsely attribute writes to the
			// connector instead of this independently executed process.
			file, err := writer.File()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command("/usr/bin/printf", suffix)
			command.Stdout = file
			command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
			command.Dir = "/"
			runErr := command.Run()
			closeErr := file.Close()
			if runErr != nil || closeErr != nil {
				t.Fatal("independent fragment writer setup failed")
			}
			if err := peer.alive(); err != nil {
				t.Fatal("connector did not remain live during the fragment control")
			}
			_, err = readUnixFrame(reader, peer)
			if err == nil {
				t.Fatal("acceptance: different frame writer")
			}
			requireCode(t, err, api.CodeForbidden)
		})
	}
}
