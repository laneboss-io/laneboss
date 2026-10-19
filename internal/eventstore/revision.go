package eventstore

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// DisplayRevision fingerprints only the fixed event-store inputs. A changed
// database, journal, ownership marker or directory invalidates the display cache.
// It creates nothing and returns no file content or filesystem metadata to HTTP.
func DisplayRevision(c *Configuration) (string, error) {
	d, err := c.OpenDirectory(false)
	if err != nil {
		return "", err
	}
	if d == nil {
		return "missing", nil
	}
	defer d.Close()
	marker, err := d.Marker()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	fmt.Fprint(h, c.StatePath, Canonical(marker), revisionIdentity(d.identity))
	for _, name := range []string{storeFile, storeFile + "-wal", storeFile + "-journal"} {
		info, err := os.Lstat(filepath.Join(d.Path, name))
		if os.IsNotExist(err) {
			fmt.Fprint(h, name, "missing")
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return "", Integrity("a display input is not a regular file")
		}
		fmt.Fprint(h, name, info.Size(), info.ModTime().UnixNano(), revisionIdentity(info))
	}
	if err := d.checkIdentity(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func revisionIdentity(info os.FileInfo) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
	}
	return info.Name()
}
