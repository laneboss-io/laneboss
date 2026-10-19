//go:build linux

package admin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) != 2 || os.Args[1] != "admin-audit-lifetime" {
		return
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 2<<20))
	if err != nil || len(data) < 256 {
		os.Exit(81)
	}
	if n, err := os.Stderr.Write(data[:256]); err != nil || n != 256 {
		os.Exit(82)
	}
	ready, release := os.NewFile(3, "audit-ready"), os.NewFile(4, "audit-release")
	if n, err := ready.Write([]byte{'r'}); err != nil || n != 1 {
		os.Exit(83)
	}
	var allow [1]byte
	if _, err := io.ReadFull(release, allow[:]); err != nil || allow[0] != 'x' {
		os.Exit(84)
	}
	if n, err := os.Stderr.Write(data[256:]); err != nil || n != len(data)-256 {
		os.Exit(85)
	}
	os.Exit(0)
}

func TestGateStderrLifetime(t *testing.T) {
	file, err := os.CreateTemp(privateTestDir(t), "capture-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	releaseRead, releaseWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRead.Close()
	defer releaseWrite.Close()
	seed, err := randomID("audit-")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(strings.Repeat(string(seed), 16384))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "admin-audit-lifetime")
	cmd.Env, cmd.Stdin, cmd.ExtraFiles = []string{}, bytes.NewReader(payload), []*os.File{readyWrite, releaseRead}
	observer, err := attachBootstrapStderr(cmd, file)
	if err != nil {
		t.Fatal("valid capture sink was refused")
	}
	defer observer.close()
	ownedHandle := observer.owned
	if ownedHandle == nil {
		t.Fatal("valid capture did not retain a descriptor")
	}
	defer ownedHandle.Close()
	if cmd.WaitDelay != 0 {
		t.Fatal("acceptance: gate stderr installed a truncating wait timer")
	}
	if err := cmd.Start(); err != nil {
		t.Fatal("audit lifetime child did not start")
	}
	finished := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		if closeErr := observer.close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		finished <- err
	}()
	waited := false
	t.Cleanup(func() {
		if !waited {
			cancel()
			<-finished
		}
	})
	if err := readyRead.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ready [1]byte
	if _, err := io.ReadFull(readyRead, ready[:]); err != nil || ready[0] != 'r' {
		t.Fatal("audit fixture did not reach readiness")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		prefix, err := os.ReadFile(file.Name())
		if err != nil {
			t.Fatal(err)
		}
		if len(prefix) == 256 && bytes.Equal(prefix, payload[:256]) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("audit fixture did not forward its pre-readiness prefix")
		}
		time.Sleep(time.Millisecond)
	}
	observer.freeze()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := releaseWrite.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	waitErr := <-finished
	waited = true
	actual, err := os.ReadFile(file.Name())
	if waitErr != nil || err != nil || !bytes.Equal(actual, payload) {
		t.Fatal("acceptance: gate lifetime stderr lost bytes after readiness and caller close")
	}
	observer.mu.Lock()
	owned, prefix := observer.owned, append([]byte(nil), observer.prefix...)
	observer.mu.Unlock()
	if owned != nil || len(prefix) != 256 || !bytes.Equal(prefix, payload[:256]) {
		t.Fatal("acceptance: gate stderr owner did not drain/close or mutated its frozen prefix")
	}
	if n, err := ownedHandle.Write([]byte{'!'}); n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatal("acceptance: gate stderr retained a writable owner after final drain")
	}
}

func TestGateStderrInputs(t *testing.T) {
	file, err := os.CreateTemp(privateTestDir(t), "sink-")
	if err != nil {
		t.Fatal(err)
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	readOnly, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	for _, item := range []struct {
		name string
		file *os.File
	}{{"nil", nil}, {"closed", file}, {"read-only", readOnly}} {
		t.Run(item.name, func(t *testing.T) {
			cmd := exec.Command("/usr/bin/true")
			observer, err := attachBootstrapStderr(cmd, item.file)
			if observer != nil {
				defer observer.close()
			}
			var typed *api.Error
			if observer != nil || !errors.As(err, &typed) || cmd.Process != nil || cmd.Stderr != nil {
				t.Fatal("acceptance: refused stderr sink acquired a capture owner or started a child")
			}
		})
	}
}
