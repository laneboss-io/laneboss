package start

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const markerName = ".laneboss-state"

var storeID = rx(`^[0-9a-f]{32}$`)
var recordedTime = rx(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$`)

func exactKeys(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			return false
		}
	}
	return true
}
func validMarker(value any) bool {
	m, ok := value.(map[string]any)
	if !ok || !exactKeys(m, "config", "format", "store") || !nameRE.MatchString(str(m["config"])) {
		return false
	}
	format, ok := intValue(m["format"])
	if !ok || format != 2 {
		return false
	}
	if m["store"] == nil {
		return true
	}
	s, ok := m["store"].(map[string]any)
	return ok && exactKeys(s, "id", "created_at") && storeID.MatchString(str(s["id"])) && recordedTime.MatchString(str(s["created_at"]))
}
func readMarker(path string) any {
	data, err := readRegular(path, 65536)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return "unreadable"
	}
	value, err := parseJSON(data)
	if err != nil {
		return "unreadable"
	}
	if _, ok := value.(map[string]any); !ok {
		return "unreadable"
	}
	return value
}
func (c *configuration) markerOwner(v any) string {
	if v == nil {
		return ""
	}
	m, ok := v.(map[string]any)
	if !ok {
		return "(unreadable)"
	}
	owner := str(m["config"])
	if owner == c.name {
		return c.name
	}
	if validMarker(v) {
		for _, other := range c.others {
			if owner == other.name {
				return owner
			}
		}
	}
	return "(another or an unknown configuration)"
}
func (c *configuration) checkStateChain() error {
	p := resolved(c.state)
	existing := p
	for {
		if _, err := os.Stat(existing); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return refused("cannot open the state directory " + scrub(c.state))
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			break
		}
		existing = parent
	}
	first := true
	for current := existing; ; current = filepath.Dir(current) {
		marker := readMarker(filepath.Join(current, markerName))
		owner := c.markerOwner(marker)
		own := first && existing == p
		if owner != "" && owner != c.name {
			if own {
				if owner == "(unreadable)" {
					return refused("the ownership marker of the state directory " + scrub(c.state) + " is unreadable, a link or not a regular file")
				}
				if strings.HasPrefix(owner, "(") {
					return refused("the state directory " + scrub(c.state) + " belongs to another or an unknown configuration")
				}
				return refused("the state directory " + scrub(c.state) + " belongs to configuration " + shown(owner))
			}
			if owner == "(unreadable)" {
				return refused("the state directory " + scrub(c.state) + " lies below a directory whose ownership marker is unreadable")
			}
			if strings.HasPrefix(owner, "(") {
				return refused("the state directory " + scrub(c.state) + " lies inside the state directory of another or an unknown configuration")
			}
			return refused("the state directory " + scrub(c.state) + " lies inside the state directory of configuration " + shown(owner))
		}
		if !own && owner == c.name {
			return refused("the state directory lies inside another state directory of " + shown(c.name))
		}
		first = false
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}
func (c *configuration) isolation() (bool, string, bool) {
	problems := c.zoneProblems()
	ownProblem := len(problems) > 0
	if err := c.checkStateChain(); err != nil {
		problems = append(problems, err.Error())
		ownProblem = true
	}
	if info, err := os.Stat(c.state); err == nil && info.IsDir() {
		real := resolved(c.state)
		err := filepath.WalkDir(real, func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path != real && e.IsDir() {
				if _, err := os.Lstat(filepath.Join(path, markerName)); err == nil {
					problems = append(problems, "the state directory contains another state directory, "+scrub(path))
					ownProblem = true
					return fs.SkipAll
				}
			}
			return nil
		})
		if err != nil {
			problems = append(problems, "a file-system error stopped this check")
			ownProblem = true
		}
	}
	for _, other := range c.unreadable {
		problems = append(problems, "configuration "+shown(other.name)+" cannot be read ("+other.why+"), so its state directory cannot be compared")
	}
	if len(problems) > 0 {
		return false, strings.Join(problems, "; "), ownProblem
	}
	return true, scrub(c.state) + " is used by configuration " + c.name + " alone", false
}
func readRegular(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, refused("the file is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, refused("the file is larger than its permitted limit")
	}
	return data, nil
}

// Read all state children through a pinned root, rejecting links in every part.
func readState(root *os.Root, relative string, limit int64) ([]byte, error) {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	path := ""
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, integrity("invalid path in the state directory")
		}
		path = filepath.Join(path, part)
		info, err := root.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, integrity("a state file or directory is a symbolic link")
		}
	}
	f, err := root.OpenFile(relative, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, integrity("a state file is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, integrity("a state file is larger than its permitted limit")
	}
	return data, nil
}
func stateEntries(root *os.Root, relative string) ([]os.DirEntry, error) {
	if relative != "." {
		info, err := root.Lstat(relative)
		if os.IsNotExist(err) {
			return []os.DirEntry{}, nil
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, integrity("a state directory is a link or is not a directory")
		}
	}
	f, err := root.Open(relative)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	return entries, err
}
func pendingCounts(root *os.Root, lane string) (int, int, error) {
	if !laneRE.MatchString(lane) {
		return 0, 0, integrity("invalid lane name in the projection")
	}
	relative := filepath.Join("lanes", lane)
	if entries, err := stateEntries(root, "lanes"); err != nil {
		return 0, 0, err
	} else if len(entries) == 0 {
		return 0, 0, nil
	}
	entries, err := stateEntries(root, relative)
	if err != nil {
		return 0, 0, err
	}
	waiting, refused := 0, 0
	for _, e := range entries {
		name := e.Name()
		isWaiting := name == "pending.jsonl" || strings.HasPrefix(name, "pending-") && strings.HasSuffix(name, ".jsonl")
		if !isWaiting && name != "refused.jsonl" {
			continue
		}
		data, err := readState(root, filepath.Join(relative, name), 16*1024*1024)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return 0, 0, refusedError(name)
		}
		count := 0
		for _, line := range splitLines(string(data)) {
			if strings.TrimSpace(line) != "" {
				count++
			}
		}
		if isWaiting {
			waiting += count
		} else {
			refused += count
		}
	}
	return waiting, refused, nil
}
func refusedError(file string) error {
	return &problem{2, "refused", fmt.Sprintf("%s: cannot read a regular file inside the lane directory", shown(file))}
}
