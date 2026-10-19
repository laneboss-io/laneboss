//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Actual Unix endpoint/accept/read/write lifetimes exercise a pending read
// that requires a callback on another connection. This tests transport
// reentrancy; the existing frame/peer/allowlist tests own RPC authentication.
func TestCredentialMetadataConcurrentReaders(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("native metadata listener canary requires the disposable Linux root box")
	}
	id, err := randomID("metadata-")
	if err != nil {
		t.Fatal(err)
	}
	b := installation{Config: string(id[:23]), Service: account{GID: uint32(os.Getegid())}}
	if err := os.MkdirAll(b.runtimePath(), 0750); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(b.runtimePath())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered := make(chan struct{})
	resume := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(resume) }) }
	var readers atomic.Int32
	stop, err := startCredentialMetadataReader(ctx, b, func(ctx context.Context, connection *net.UnixConn) error {
		defer connection.Close()
		var data [8]byte
		if _, err := io.ReadFull(connection, data[:]); err != nil {
			return err
		}
		if readers.Add(1) == 1 {
			close(entered)
			select {
			case <-resume:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		_, err := connection.Write(data[:])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	}()
	defer release()
	dial := func() *net.UnixConn {
		t.Helper()
		connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: b.credentialMetadataPath(), Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			connection.Close()
			t.Fatal(err)
		}
		return connection
	}
	first := dial()
	defer first.Close()
	var original, callback [8]byte
	if _, err := rand.Read(original[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(callback[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write(original[:]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first native metadata reader did not become pending")
	}
	second := dial()
	defer second.Close()
	if _, err := second.Write(callback[:]); err != nil {
		t.Fatal(err)
	}
	var actual [8]byte
	if _, err := io.ReadFull(second, actual[:]); err != nil || !bytes.Equal(actual[:], callback[:]) {
		t.Fatal("acceptance: native metadata callback could not complete while its original read awaited it", err)
	}
	release()
	if _, err := io.ReadFull(first, actual[:]); err != nil || !bytes.Equal(actual[:], original[:]) {
		t.Fatal("acceptance: original native metadata reader lost its real response after the callback", err)
	}
	if readers.Load() != 2 {
		t.Fatal("acceptance: native metadata callback did not run as a distinct reader")
	}
}
