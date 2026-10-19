//go:build linux

package admin

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestCaptureSnapshotCheckpoint(t *testing.T) {
	root, err := os.OpenRoot(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	writer, err := root.OpenFile("marker", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := unix.Flock(int(writer.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	reader, err := lockCaptureSnapshot(root)
	if reader != nil {
		reader.Close()
	}
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeUnavailable || !typed.Retryable {
		t.Fatal("snapshot ignored an actual in-progress spool checkpoint", err)
	}
	if err := unix.Flock(int(writer.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	reader, err = lockCaptureSnapshot(root)
	if err != nil {
		t.Fatal("snapshot did not resume after the same checkpoint", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureUpdateCheckpoint(t *testing.T) {
	root, err := os.OpenRoot(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	writer, err := root.OpenFile("marker", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := root.OpenFile("marker", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := unix.Flock(int(reader.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(reader.Fd()), unix.LOCK_UN)
	content, err := randomID("checkpoint-")
	if err != nil {
		t.Fatal(err)
	}
	entered, started, done := make(chan struct{}, 1), make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		done <- captureSpoolUpdate(writer, func() error {
			entered <- struct{}{}
			if _, err := writer.WriteString(string(content)); err != nil {
				return err
			}
			return writer.Sync()
		})
	}()
	<-started
	select {
	case <-entered:
		t.Fatal("spool update entered while the real snapshot checkpoint was owned")
	case <-time.After(100 * time.Millisecond):
	}
	if err := unix.Flock(int(reader.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("same spool update did not resume after checkpoint release")
	}
	actual, err := root.ReadFile("marker")
	if err != nil || string(actual) != string(content) {
		t.Fatal("checkpoint lost the actual resumed update", err)
	}
}
