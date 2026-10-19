package lane

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
)

type archiveEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Size   int64  `json:"size"`
	Mode   int64  `json:"mode"`
	SHA256 string `json:"sha256"`
	Link   string `json:"link,omitempty"`
	source string
	data   []byte
}

const archiveManifestLimit = 32 * 1024 * 1024

// The full removal plan belongs to this hashed artifact, never an event payload.
type archiveManifest struct {
	Format      int            `json:"format"`
	Entries     []archiveEntry `json:"entries"`
	RemovePaths []string       `json:"remove_paths"`
	RemoveHash  string         `json:"remove_paths_sha256"`
	ReportHash  string         `json:"report_record_sha256,omitempty"`
}

func manifestBytes(manifest *archiveManifest) ([]byte, error) {
	data, err := json.MarshalIndent(manifest, "", "  ")
	return append(data, '\n'), err
}

func archiveFile(path, name string) (archiveEntry, error) {
	entry := archiveEntry{Path: filepath.ToSlash(name), source: path}
	info, err := os.Lstat(path)
	if err != nil {
		return entry, err
	}
	entry.Mode = int64(info.Mode().Perm())
	switch {
	case info.IsDir():
		entry.Type, entry.SHA256 = "directory", digest(nil)
	case info.Mode()&os.ModeSymlink != 0:
		entry.Type = "symlink"
		entry.Link, err = os.Readlink(path)
		entry.SHA256 = digest([]byte(entry.Link))
	case info.Mode().IsRegular():
		entry.Type, entry.Size = "file", info.Size()
		var file *os.File
		file, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err == nil {
			hash := sha256.New()
			var n int64
			n, err = io.Copy(hash, file)
			closeErr := file.Close()
			if err == nil {
				err = closeErr
			}
			if err == nil && n != entry.Size {
				err = refuse("an archive input changed while hashing; nothing was removed")
			}
			entry.SHA256 = hex.EncodeToString(hash.Sum(nil))
		}
	default:
		err = refuse("an archive input is not a regular file, directory or symbolic link")
	}
	return entry, err
}

func archiveTree(path, prefix string) ([]archiveEntry, error) {
	entries := []archiveEntry{}
	// Walk relative to one fixed root, and never follow worktree symlinks.
	err := filepath.WalkDir(path, func(current string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(path, current)
		if err != nil {
			return err
		}
		entry, err := archiveFile(current, filepath.Join(prefix, relative))
		if err == nil {
			entries = append(entries, entry)
		}
		return err
	})
	return entries, err
}

func archiveLogs(path string) ([]archiveEntry, error) {
	entries := []archiveEntry{}
	err := filepath.WalkDir(path, func(current string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return refuse("a lane archive input is a symbolic link; nothing was removed")
		}
		relative, err := filepath.Rel(path, current)
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(relative, ".log") || relative == "report.md") {
			entry, err := archiveFile(current, filepath.Join("lane", relative))
			if err != nil {
				return err
			}
			entries = append(entries, entry)
		}
		return nil
	})
	return entries, err
}

func writeLaneTar(root *os.Root, name string, entries []archiveEntry) (string, error) {
	file, err := childOpen(root, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	writer := tar.NewWriter(file)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.Path, Mode: entry.Mode, Size: entry.Size}
		switch entry.Type {
		case "directory":
			header.Typeflag = tar.TypeDir
		case "symlink":
			header.Typeflag, header.Linkname = tar.TypeSymlink, entry.Link
		case "file":
			header.Typeflag = tar.TypeReg
		}
		if err = writer.WriteHeader(header); err != nil {
			break
		}
		if entry.Type == "file" {
			if entry.data != nil {
				_, err = io.Copy(writer, bytes.NewReader(entry.data))
			} else {
				var source *os.File
				source, err = os.OpenFile(entry.source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
				if err == nil {
					_, err = io.Copy(writer, source)
					closeErr := source.Close()
					if err == nil {
						err = closeErr
					}
				}
			}
			if err != nil {
				break
			}
		}
	}
	if closeErr := writer.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	entry, err := archiveFile(filepath.Join(root.Name(), name), name)
	return entry.SHA256, err
}

// verifyLaneTar opens the on-disk tar and manifest afresh. It checks every
// member, including symlink targets, and rejects extra/missing/duplicate members.
// It does not extract or trust a tar-provided filesystem path.
func verifyLaneTar(root *os.Root, name, manifestName, expectedHash string, expected *archiveManifest) error {
	data, err := rootRead(root, manifestName, archiveManifestLimit)
	if err != nil {
		return err
	}
	var manifest archiveManifest
	if err = json.Unmarshal(data, &manifest); err != nil {
		return integrity("archive manifest is unreadable; nothing was removed")
	}
	comparison, err := manifestBytes(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(comparison, data) || manifest.Format != 1 || manifest.RemoveHash != digest(canonical(manifest.RemovePaths)) {
		return integrity("archive manifest changed; nothing was removed")
	}
	file, err := childOpen(root, name, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	reader := tar.NewReader(io.TeeReader(file, hash))
	seen := []archiveEntry{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return integrity("archive tar read-back failed; nothing was removed")
		}
		entry := archiveEntry{Path: header.Name, Mode: header.Mode, Size: header.Size}
		switch header.Typeflag {
		case tar.TypeDir:
			entry.Type, entry.SHA256 = "directory", digest(nil)
		case tar.TypeSymlink:
			entry.Type, entry.Link, entry.SHA256 = "symlink", header.Linkname, digest([]byte(header.Linkname))
		case tar.TypeReg, tar.TypeRegA:
			entry.Type = "file"
			h := sha256.New()
			if _, err = io.Copy(h, reader); err != nil {
				return integrity("archive member read-back failed; nothing was removed")
			}
			entry.SHA256 = hex.EncodeToString(h.Sum(nil))
		default:
			return integrity("archive tar contains an unsupported member; nothing was removed")
		}
		seen = append(seen, entry)
	}
	if _, err = io.Copy(hash, file); err != nil {
		return integrity("archive hash read-back failed; nothing was removed")
	}
	if hex.EncodeToString(hash.Sum(nil)) != expectedHash || !reflect.DeepEqual(manifest.Entries, seen) {
		return integrity("archive manifest does not match tar read-back; nothing was removed")
	}
	return nil
}

func sortArchive(entries []archiveEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
}
