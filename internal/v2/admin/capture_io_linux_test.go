//go:build linux

package admin

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func spoolFixture(t *testing.T, bound int64) (*os.Root, api.CaptureBinding, [2]*os.File, <-chan error) {
	return spoolFixtureReady(t, bound, nil)
}

func spoolFixtureReady(t *testing.T, bound int64, ready func(*os.Root, api.CaptureBinding) error) (*os.Root, api.CaptureBinding, [2]*os.File, <-chan error) {
	t.Helper()
	root, err := os.OpenRoot(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	var files []*os.File
	for _, name := range []string{"stdout", "stderr", "marker"} {
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	var reads, writes [2]*os.File
	for index := range reads {
		reads[index], writes[index], err = os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
	}
	binding := api.CaptureBinding{ID: "actual-pipe-binding", Streams: []api.CaptureStreamBinding{{ID: "actual-out", Stream: "stdout", PipeID: "owned-out-pipe"}, {ID: "actual-err", Stream: "stderr", PipeID: "owned-err-pipe"}}}
	finished := make(chan error, 1)
	var attest func() error
	if ready != nil {
		attest = func() error { return ready(root, binding) }
	}
	go func() {
		finished <- spoolPipesReady(spoolInput{BindingID: binding.ID, Streams: binding.Streams, MaxBytes: bound}, reads, [2]*os.File{files[0], files[1]}, files[2], attest)
	}()
	t.Cleanup(func() {
		for _, write := range writes {
			write.Close()
		}
	})
	return root, binding, writes, finished
}

func TestCaptureReadySpool(t *testing.T) {
	ready := make(chan error, 1)
	_, _, writes, finished := spoolFixtureReady(t, 1024, func(root *os.Root, binding api.CaptureBinding) error {
		marker, err := readSpool(root, binding)
		if err == nil && (len(marker.Positions) != 2 || marker.Positions[0].Bytes != 0 || marker.Positions[1].Bytes != 0 || marker.Positions[0].PipeEOF || marker.Positions[1].PipeEOF) {
			err = errors.New("initial spool does not match its actual empty pipe state")
		}
		ready <- err
		return err
	})
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal("acceptance: capture readiness preceded durable empty spool")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("capture readiness did not arrive")
	}
	for _, write := range writes {
		if err := write.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := waitSpool(t, finished); err != nil {
		t.Fatal(err)
	}
}

func waitSpool(t *testing.T, finished <-chan error) error {
	t.Helper()
	select {
	case err := <-finished:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("actual capture pipe did not reach its bounded outcome")
		return context.DeadlineExceeded
	}
}

func TestCaptureSpoolExactBytes(t *testing.T) {
	root, binding, writes, finished := spoolFixture(t, 4096)
	data := make([]byte, 131)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if n, err := writes[0].Write(data); err != nil || n != len(data) {
		t.Fatal("actual stdout fixture write failed")
	}
	if n, err := writes[1].Write(data[19:]); err != nil || n != len(data)-19 {
		t.Fatal("actual stderr fixture write failed")
	}
	for _, write := range writes {
		if err := write.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := waitSpool(t, finished); err != nil {
		t.Fatal(err)
	}
	marker, err := readSpool(root, binding)
	if err != nil || len(marker.Positions) != 2 || marker.Positions[0].Bytes != int64(len(data)) || marker.Positions[0].SHA256 != digestBytes(data) ||
		marker.Positions[1].SHA256 != digestBytes(data[19:]) || !marker.Positions[0].PipeEOF || !marker.Positions[1].PipeEOF || marker.Failure != "" {
		t.Fatal("acceptance: spool bytes, ranges or actual pipe EOF differ")
	}
	file, err := root.OpenFile("stdout", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 0xff
	if n, err := file.WriteAt(data[:1], 0); err != nil || n != 1 {
		t.Fatal("spool counterfactual did not change bytes")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readSpool(root, binding); err == nil {
		t.Fatal("acceptance: changed retained spool bytes were accepted")
	}
}

func TestCaptureSpoolBound(t *testing.T) {
	root, binding, writes, finished := spoolFixture(t, 17)
	data := make([]byte, 257)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if n, err := writes[0].Write(data); err != nil || n != len(data) {
		t.Fatal("spool-bound fixture write failed")
	}
	for _, write := range writes {
		if err := write.Close(); err != nil {
			t.Fatal(err)
		}
	}
	err := waitSpool(t, finished)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeUnavailable {
		t.Fatal("acceptance: unacknowledged spool exceeded its bound")
	}
	marker, err := readSpool(root, binding)
	if err != nil || marker.Failure != "spool_full" || marker.GapStreamID != binding.Streams[0].ID || marker.LostBytes <= 0 || marker.Positions[0].PipeEOF || marker.Positions[0].Bytes > 17 {
		t.Fatal("acceptance: full spool fabricated EOF or omitted its retained failure range")
	}
}

func TestPrivateCollectionInventory(t *testing.T) {
	root, record, _ := storageFixture(t)
	if err := syncStorageDirectories(context.Background(), root, &record, uint32(os.Geteuid()), true); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(string(record.Storage.Binding.WorkspaceID), "real-file")
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("actual private file bytes")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	inventory, err := inventoryStorage(context.Background(), root, record)
	if err != nil || len(inventory) != 4 {
		t.Fatalf("actual private inventory failed: %v", err)
	}
	if err := os.Link(filepath.Join(root.Name(), name), filepath.Join(root.Name(), name+"-alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := inventoryStorage(context.Background(), root, record); err == nil {
		t.Fatal("acceptance: unresolved private hard link entered collection")
	}
}

func TestPrivateDescriptorReferences(t *testing.T) {
	file, err := os.CreateTemp(privateTestDir(t), "held-private-")
	if err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("actual file has no native inode")
	}
	inventory := []storageInode{{Device: uint64(stat.Dev), Inode: stat.Ino}}
	count, _, err := descriptorReferences(context.Background(), os.Getpid(), inventory)
	if err != nil || count == 0 {
		t.Fatal("acceptance: open private descriptor was measured as zero")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	count, _, err = descriptorReferences(context.Background(), os.Getpid(), inventory)
	if err != nil || count != 0 {
		t.Fatalf("closed descriptor control retained an actual reference: %v", err)
	}
}
