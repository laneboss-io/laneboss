package lane

import (
	"io/fs"
	"os"
	"path/filepath"
)

// A kernel path alone does not reveal a second name for the same inode. Inspect
// zone metadata without following symlinks or reading any file's contents.
func HardlinkInZones(info os.FileInfo, zones []string) (bool, error) {
	visited := 0
	for _, zone := range zones {
		if zone == "" {
			continue
		}
		root := realPath(zone)
		if _, err := os.Lstat(root); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return false, err
		}
		found := false
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			visited++
			if visited > 65536 {
				return refuse("hard-link metadata exceeds the inspection bound")
			}
			if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
				return nil
			}
			other, err := entry.Info()
			if err != nil {
				return err
			}
			if other.Mode().IsRegular() && os.SameFile(info, other) {
				found = true
				return fs.SkipAll
			}
			return nil
		})
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}
