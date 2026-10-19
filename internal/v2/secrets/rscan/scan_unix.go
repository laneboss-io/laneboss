//go:build linux || darwin

package rscan

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func scanReuseChild(ctx context.Context, key []byte, home, name string) APIKeyPlaceResult {
	return scanReuseTree(ctx, key, filepath.Join(home, name), false, nil)
}

func scanReuseTree(ctx context.Context, key []byte, path string, required bool, expected os.FileInfo) (result APIKeyPlaceResult) {
	unreadablePath := path
	defer func() {
		if result.Unreadable && result.UnreadablePath == "" {
			result.UnreadablePath = redactReusePath(unreadablePath, key)
		}
	}()
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		result.Unreadable = true
		return result
	}
	// A root or an ancestor link is not a missing optional credential file.
	// Walk from / with no-follow opens rather than resolving an untrusted path.
	root, err := os.OpenRoot("/")
	if err != nil {
		result.Unreadable = true
		return result
	}
	defer func() {
		if root.Close() != nil {
			result.Unreadable = true
		}
	}()
	parts := reusePathParts(path)
	unreadablePath = "/"
	for _, part := range parts[:len(parts)-1] {
		unreadablePath = filepath.Join(unreadablePath, part)
		info, err := root.Lstat(part)
		if errors.Is(err, os.ErrNotExist) && !required {
			return result
		}
		if err != nil || !info.IsDir() || info.Mode().Perm()&0500 != 0500 {
			result.Unreadable = true
			return result
		}
		next, err := root.OpenRoot(part)
		if err != nil {
			result.Unreadable = true
			return result
		}
		actual, statErr := next.Stat(".")
		if statErr != nil || !os.SameFile(info, actual) {
			next.Close()
			result.Unreadable = true
			return result
		}
		if err := root.Close(); err != nil {
			next.Close()
			result.Unreadable = true
			return result
		}
		root = next
	}
	unreadablePath = path
	name := parts[len(parts)-1]
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) && !required {
		return result
	}
	if err != nil {
		result.Unreadable = true
		return result
	}
	result.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		result.Unreadable = true
		return result
	}
	if expected != nil && (!info.IsDir() || !os.SameFile(info, expected)) {
		result.Unreadable = true
		return result
	}
	var count uint64
	if err := visitReuseTree(ctx, root, name, path, key, &result, &count); err != nil {
		result.Unreadable = true
	}
	return result
}

func reusePathParts(path string) []string {
	var parts []string
	for path != "/" {
		parts = append(parts, filepath.Base(path))
		path = filepath.Dir(path)
	}
	if len(parts) == 0 {
		return []string{"."}
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

func visitReuseTree(ctx context.Context, root *os.Root, name, path string, key []byte, result *APIKeyPlaceResult, count *uint64) (resultErr error) {
	defer func() {
		if resultErr != nil && result.UnreadablePath == "" {
			result.UnreadablePath = redactReusePath(path, key)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	*count += 1
	if *count > 100000 {
		return io.ErrNoProgress
	}
	matchReuse([]byte(name), key, path, result)
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		link, err := root.Readlink(name)
		if err != nil {
			return err
		}
		matchReuse([]byte(link), key, path, result)
		result.Links++
		return nil
	case info.IsDir():
		if info.Mode().Perm()&0500 != 0500 {
			return os.ErrPermission
		}
		child, err := root.OpenRoot(name)
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, child.Close()) }()
		actual, err := child.Stat(".")
		if err != nil || !os.SameFile(info, actual) {
			return os.ErrInvalid
		}
		dir, err := child.Open(".")
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, dir.Close()) }()
		for {
			entries, readErr := dir.ReadDir(128)
			for _, entry := range entries {
				if err := visitReuseTree(ctx, child, entry.Name(), filepath.Join(path, entry.Name()), key, result, count); err != nil {
					return err
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
		return nil
	case info.Mode().IsRegular():
		if info.Mode().Perm()&0444 == 0 {
			return os.ErrPermission
		}
		return scanReuseFile(ctx, root, name, path, key, info, result)
	default:
		// Sockets, pipes and devices cannot prove absence of persistent bytes.
		return os.ErrInvalid
	}
}

func scanReuseFile(ctx context.Context, root *os.Root, name, path string, key []byte, expected os.FileInfo, result *APIKeyPlaceResult) error {
	const attempts = 8 // backoff doubles from 10 ms: about 1.3 s for a busy writer to settle
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		before, err := file.Stat()
		if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0444 == 0 || !os.SameFile(expected, before) {
			return errors.Join(os.ErrInvalid, file.Close())
		}
		// Bound each attempt to the size observed on its held descriptor. Any
		// append/truncate or mtime change requires a fresh complete read; a busy
		// writer cannot extend this attempt forever. Keep matches from EVERY
		// attempt, even if a later stable version no longer contains them.
		n, _, readErr := scanReuseReader(ctx, io.LimitReader(file, before.Size()), key, path, result)
		after, statErr := file.Stat()
		named, nameErr := root.Lstat(name)
		closeErr := file.Close()
		if readErr != nil || statErr != nil || nameErr != nil || closeErr != nil {
			return os.ErrInvalid
		}
		if !after.Mode().IsRegular() || !named.Mode().IsRegular() || after.Mode().Perm()&0444 == 0 || named.Mode().Perm()&0444 == 0 ||
			!os.SameFile(expected, after) || !os.SameFile(expected, named) {
			return os.ErrInvalid
		}
		if n == before.Size() && before.Size() == after.Size() && after.Size() == named.Size() &&
			before.ModTime().Equal(after.ModTime()) && after.ModTime().Equal(named.ModTime()) {
			result.Files++
			return nil
		}
		if attempt+1 < attempts {
			timer := time.NewTimer((10 * time.Millisecond) << attempt)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return os.ErrInvalid
}
