package dataworker

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func jobParent(root *os.Root, name string) (*os.File, string, error) {
	if err := manifest.Relative(name); err != nil {
		return nil, "", err
	}
	if name == "." {
		return nil, "", manifest.Invalid("job mutation cannot replace its held root")
	}
	parent, err := openJobPath(root, path.Dir(name), os.O_RDONLY|unix.O_DIRECTORY, 0)
	return parent, path.Base(name), err
}

func mkdirJobPath(root *os.Root, name string) error {
	parent, base, err := jobParent(root, name)
	if err != nil {
		return err
	}
	return errors.Join(unix.Mkdirat(int(parent.Fd()), base, 0700), parent.Close())
}

func symlinkJobPath(root *os.Root, target, name string) error {
	parent, base, err := jobParent(root, name)
	if err != nil {
		return err
	}
	return errors.Join(unix.Symlinkat(target, int(parent.Fd()), base), parent.Close())
}

func readlinkJobPath(root *os.Root, name string) (string, error) {
	parent, base, err := jobParent(root, name)
	if err != nil {
		return "", err
	}
	buffer := make([]byte, 4097)
	n, readErr := unix.Readlinkat(int(parent.Fd()), base, buffer)
	err = errors.Join(readErr, parent.Close())
	if err != nil {
		return "", err
	}
	if n == len(buffer) {
		return "", manifest.Invalid("job symlink exceeds its manifest bound")
	}
	return string(buffer[:n]), nil
}

// WalkDir opens only directories. Its recursion uses the same nonfollowing
// component walk as file reads and chmod handoff, including a raced directory.
type jobDirectoryFS struct{ root *os.Root }

func (f jobDirectoryFS) Open(name string) (fs.File, error) {
	return openJobPath(f.root, name, os.O_RDONLY|unix.O_DIRECTORY, 0)
}

func prepareJobHome(ctx context.Context, root *os.Root, vendor string) error {
	if err := manifest.Relative(vendor); err != nil {
		return err
	}
	if vendor == "." {
		return manifest.Invalid("vendor home must be below its private root")
	}
	expected := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: ".", Kind: "directory", Mode: 0700}}}
	parts := strings.Split(vendor, "/")
	for i := range parts {
		if err := checkContext(ctx); err != nil {
			return err
		}
		name := strings.Join(parts[:i+1], "/")
		if err := mkdirJobPath(root, name); err != nil {
			return err
		}
		expected.Entries = append(expected.Entries, api.ObjectEntry{Path: name, Kind: "directory", Mode: 0700})
	}
	return verifyJobTree(ctx, root, expected, 0)
}
