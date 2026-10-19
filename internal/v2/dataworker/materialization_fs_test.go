package dataworker

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func privateJobRoot(t *testing.T) (string, *os.Root) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	facts, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || facts.Uid != uint32(os.Getuid()) {
		t.Fatal("job fixture root is not an ordinary owned private directory")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return path, root
}

func TestJobOpenNoFollow(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			base, root := privateJobRoot(t)
			if err := os.Mkdir(filepath.Join(base, "real"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(base, "real", "canary"), []byte("observable"), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := openJobPath(root, "real/canary", os.O_RDONLY, 0)
			if err != nil {
				t.Fatal("job open regular control failed", err)
			}
			actual, readErr := io.ReadAll(file)
			if err := errors.Join(readErr, file.Close()); err != nil || string(actual) != "observable" {
				t.Fatal("job open could not observe its regular control", err)
			}
			target, link, name := "real/canary", "alias", "alias"
			if kind == "directory" {
				target, name = "real", "alias/canary"
			}
			if err := os.Symlink(target, filepath.Join(base, link)); err != nil {
				t.Fatal(err)
			}
			file, err = openJobPath(root, name, os.O_RDONLY, 0)
			if err == nil {
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				t.Fatal("job open followed a symlink component")
			}
		})
	}
}

func TestJobOpenNonblocking(t *testing.T) {
	base, root := privateJobRoot(t)
	// Keep a real FIFO peer open so a missing NONBLOCK flag is an immediate
	// flag assertion failure, never a hanging red test or a timeout kill.
	name := filepath.Join(base, "fifo")
	if err := unix.Mkfifo(name, 0600); err != nil {
		t.Fatal(err)
	}
	peer, err := unix.Open(name, unix.O_RDWR|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Close(peer); err != nil {
			t.Error(err)
		}
	})
	file, err := openJobPath(root, "fifo", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(errors.Join(err, file.Close()))
	}
	var flags int
	var flagErr error
	controlErr := raw.Control(func(fd uintptr) { flags, flagErr = unix.FcntlInt(fd, unix.F_GETFL, 0) })
	if err := errors.Join(controlErr, flagErr, file.Close()); err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Fatal("job open omitted the kernel nonblocking flag", err)
	}
}
func TestJobHomeContents(t *testing.T) {
	for _, kind := range []string{"valid", "existing", "symlink", "extra"} {
		t.Run(kind, func(t *testing.T) {
			base, root := privateJobRoot(t)
			switch kind {
			case "existing":
				if err := os.Mkdir(filepath.Join(base, ".vendor"), 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Mkdir(filepath.Join(base, "target"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("target", filepath.Join(base, ".vendor")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(filepath.Join(base, "ungranted"), []byte("kept"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := prepareJobHome(context.Background(), root, ".vendor")
			if kind == "valid" {
				info, statErr := os.Lstat(filepath.Join(base, ".vendor"))
				if err != nil || statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
					t.Fatal("job home did not create its private vendor directory", errors.Join(err, statErr))
				}
			} else if err == nil {
				t.Fatal("job home accepted raced or ungranted contents")
			}
		})
	}
}

func TestJobDirectoryModes(t *testing.T) {
	sourcePath, source := privateJobRoot(t)
	_, destination := privateJobRoot(t)
	if err := os.Mkdir(filepath.Join(sourcePath, "nested"), 0750); err != nil {
		t.Fatal(err)
	}
	content := []byte("directory data\n")
	if err := os.WriteFile(filepath.Join(sourcePath, "nested", "data"), content, 0600); err != nil {
		t.Fatal(err)
	}
	ref := api.BlobRef{ID: "directory-bytes", Class: "artifact", Bytes: int64(len(content)), SHA256: manifest.Hash(content)}
	object := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
		{Path: "nested", Kind: "directory", Mode: 0750},
		{Path: "nested/data", Kind: "file", Mode: 0640, Content: &ref},
	}}
	if err := manifest.Object(object); err != nil {
		t.Fatal(err)
	}
	if err := copyJobTree(context.Background(), source, destination, object, 100); err != nil {
		t.Fatal("directory copy control failed", err)
	}
	info, err := destination.Lstat("nested")
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0750 {
		t.Fatal("directory permission handoff lost its declared mode", err)
	}
	if err := verifyJobTree(context.Background(), destination, object, 100); err != nil {
		t.Fatal("directory copy read-back failed", err)
	}
}
