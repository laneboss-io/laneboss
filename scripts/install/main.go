// The install helper publishes a built launcher and its plugin assets. It is
// built temporarily by scripts/install.sh and is not part of the installation.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"laneboss.io/laneboss/internal/identity"
)

type content struct {
	bytes []byte
	mode  fs.FileMode
	sha   string
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "install: expected source directory, prefix and built launcher")
		os.Exit(2)
	}
	if err := install(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, "install: "+err.Error())
		os.Exit(2)
	}
}

func readContent(path string, mode fs.FileMode) (content, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return content{}, err
	}
	if !info.Mode().IsRegular() {
		return content{}, fmt.Errorf("source file is not a regular file: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return content{}, err
	}
	return content{data, mode, fmt.Sprintf("%x", sha256.Sum256(data))}, nil
}

func install(root, prefix, binary string) error {
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?$`).MatchString(identity.Version) || strings.Contains(identity.Version, "..") {
		return fmt.Errorf("the package version must look like 1.2.3 or 1.2.3-label")
	}
	if prefix == "~" || strings.HasPrefix(prefix, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		prefix = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(prefix, "~"), "/"))
	}
	var err error
	prefix, err = filepath.Abs(prefix)
	if err != nil {
		return err
	}
	program, err := readContent(binary, 0755)
	if err != nil {
		return err
	}
	files := map[string]content{"bin/" + identity.Program: program}
	plugins := filepath.Join(root, "plugins")
	if _, err := os.Stat(plugins); err == nil {
		err = filepath.WalkDir(plugins, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			mode := fs.FileMode(0644)
			if info.Mode()&0111 != 0 {
				mode = 0755
			}
			data, err := readContent(path, mode)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if strings.ContainsAny(relative, "\r\n") {
				return fmt.Errorf("plugin file names must not contain line breaks")
			}
			files[filepath.ToSlash(relative)] = data
			return nil
		})
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var manifest strings.Builder
	fmt.Fprintf(&manifest, "version %s\n", identity.Version)
	for _, name := range names {
		fmt.Fprintf(&manifest, "%s  %s\n", files[name].sha, name)
	}
	versions := filepath.Join(prefix, "share", identity.Program, "versions")
	target := filepath.Join(versions, identity.Version)
	bindir := filepath.Join(prefix, "bin")
	link := filepath.Join(bindir, identity.Program)
	if err = checkLink(link); err != nil {
		return err
	}
	for _, directory := range []string{versions, bindir} {
		if err = os.MkdirAll(directory, 0755); err != nil {
			return err
		}
	}
	if _, err = os.Lstat(target); os.IsNotExist(err) {
		stage, err := os.MkdirTemp(versions, ".stage-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(stage)
		for _, name := range names {
			destination := filepath.Join(stage, filepath.FromSlash(name))
			if err = os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
				return err
			}
			file := files[name]
			if err = os.WriteFile(destination, file.bytes, file.mode); err != nil {
				return err
			}
			if err = os.Chmod(destination, file.mode); err != nil {
				return err
			}
		}
		if err = os.WriteFile(filepath.Join(stage, "MANIFEST"), []byte(manifest.String()), 0644); err != nil {
			return err
		}
		if err = os.Chmod(stage, 0755); err != nil {
			return err
		}
		if err = os.Rename(stage, target); err != nil {
			// A concurrent installation is acceptable only after the same complete
			// manifest, contents and mode checks below.
			if _, statErr := os.Lstat(target); statErr != nil {
				return err
			}
		}
	} else if err != nil {
		return err
	}
	if err = verify(target, manifest.String(), files); err != nil {
		return fmt.Errorf("version %s is already installed at %s and differs from this content: %s; installed versions are immutable, so give new content a new version, or remove the damaged version directory by hand", identity.Version, target, err)
	}
	// Check again after the build and verification; a regular existing command
	// must never be replaced by the installer's version link.
	if err = checkLink(link); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(bindir, ".laneboss-link-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	destination, err := filepath.Rel(bindir, filepath.Join(target, "bin", identity.Program))
	if err != nil {
		return err
	}
	stagedLink := filepath.Join(temporary, identity.Program)
	if err = os.Symlink(destination, stagedLink); err != nil {
		return err
	}
	if err = os.Rename(stagedLink, link); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"installed": identity.Version, "directory": target, "link": link})
}

func checkLink(link string) error {
	info, err := os.Lstat(link)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%s exists and is not a link; move it away first", link)
	}
	return nil
}

func verify(target, manifest string, files map[string]content) error {
	info, err := os.Lstat(target)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("its version directory is not a regular directory")
	}
	found := map[string]bool{}
	err = filepath.WalkDir(target, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(target, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a link", relative)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", relative)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s cannot be read", relative)
		}
		found[relative] = true
		if relative == "MANIFEST" {
			if string(data) != manifest {
				return fmt.Errorf("its manifest describes other content")
			}
			return nil
		}
		want, ok := files[relative]
		if !ok {
			return fmt.Errorf("%s is not part of the version", relative)
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != want.sha {
			return fmt.Errorf("%s was changed", relative)
		}
		if (want.mode == 0755 && info.Mode().Perm() != 0755) || (want.mode == 0644 && info.Mode().Perm()&0111 != 0) {
			return fmt.Errorf("%s has another mode (mode 755 for a program, no executable bit for any other file)", relative)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !found["MANIFEST"] {
		return fmt.Errorf("its manifest cannot be read")
	}
	for name := range files {
		if !found[name] {
			return fmt.Errorf("%s is missing", name)
		}
	}
	return nil
}
