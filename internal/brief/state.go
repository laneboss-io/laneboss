package brief

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

var (
	storeIDPattern         = regexp.MustCompile(`^[0-9a-f]{32}$`)
	recordedAtPattern      = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$`)
	protocolVersionPattern = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$`)
)

func validMarker(value map[string]any) bool {
	if len(value) != 3 {
		return false
	}
	name, ok := value["config"].(string)
	if !ok || !namePattern.MatchString(name) {
		return false
	}
	if value["format"] != json.Number("2") {
		return false
	}
	store, exists := value["store"]
	if !exists {
		return false
	}
	if store == nil {
		return true
	}
	m, ok := store.(map[string]any)
	if !ok || len(m) != 2 {
		return false
	}
	id, ok := m["id"].(string)
	if !ok || !storeIDPattern.MatchString(id) {
		return false
	}
	created, ok := m["created_at"].(string)
	return ok && recordedAtPattern.MatchString(created)
}

type stateDirectory struct {
	c   *configuration
	dir *directory
}

func (z *zones) checkStateChain(chain []fs.FileInfo, markers []any, creating bool) error {
	var unknown, unreadable bool
	for _, value := range markers[1:] {
		owner := z.markerOwner(value)
		if owner == "" || owner == z.c.name {
			continue
		}
		if owner == unknownOwner {
			unknown = true
			continue
		}
		if owner == "unreadable" {
			unreadable = true
			continue
		}
		return refused("the state directory lies inside the state directory of configuration %s", shownName(owner))
	}
	if unreadable {
		return refused("the state directory lies below a directory whose ownership marker is unreadable")
	}
	for _, other := range z.others {
		if other.location.exists() && containsIdentity(chain, other.location.chain[0]) {
			return refused("the state directory lies inside configuration %s's %s", shownName(other.name), other.kind)
		}
	}
	if unknown {
		return refused("the state directory lies inside the state directory of another or an unknown configuration")
	}
	if !creating && len(markers) > 0 && markers[0] != nil {
		owner := z.markerOwner(markers[0])
		if owner == "unreadable" {
			return refused("the ownership marker of the state directory is unreadable, a link or not a regular file")
		}
		if owner == unknownOwner {
			return refused("the state directory belongs to another or an unknown configuration")
		}
		if owner != z.c.name {
			return refused("the state directory belongs to configuration %s", shownName(owner))
		}
	}
	return nil
}

func openState(c *configuration, z *zones) (*stateDirectory, error) {
	real, err := realPath(c.stateDir)
	if err != nil {
		return nil, err
	}
	existing := real
	for {
		info, statError := os.Stat(existing)
		if statError == nil {
			if !info.IsDir() {
				return nil, refused("cannot create the state directory: an ancestor is not a directory")
			}
			break
		}
		if !errors.Is(statError, os.ErrNotExist) {
			return nil, refused("cannot inspect the state directory: %s", osReason(statError))
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return nil, refused("cannot find an existing ancestor of the state directory")
		}
		existing = parent
	}
	d, err := openDirectory(existing, "the state directory")
	if err != nil {
		return nil, err
	}
	chain, markers, err := walkUp(d)
	d.close()
	if err != nil {
		return nil, err
	}
	if existing != real {
		markers = append([]any{nil}, markers...)
	}
	if err := z.checkStateChain(chain, markers, true); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(c.stateDir, 0700); err != nil {
		return nil, refused("cannot create the state directory: %s", osReason(err))
	}
	d, err = openDirectory(c.stateDir, "the state directory")
	if err != nil {
		return nil, err
	}
	chain, markers, err = walkUp(d)
	if err == nil {
		err = z.checkStateChain(chain, markers, false)
	}
	if err != nil {
		d.close()
		return nil, err
	}
	return &stateDirectory{c, d}, nil
}

func (s *stateDirectory) marker() (map[string]any, error) {
	value := readMarker(s.dir)
	if value == nil {
		return nil, nil
	}
	m, ok := value.(map[string]any)
	if !ok || !validMarker(m) || m["config"] != s.c.name {
		return nil, integrity("the ownership marker is not a valid marker of configuration %s", shownName(s.c.name))
	}
	return m, nil
}

func (s *stateDirectory) writeMarker(store any, replace bool) error {
	data, err := canonical(map[string]any{"config": s.c.name, "format": 2, "store": store})
	if err != nil {
		return err
	}
	if err := s.dir.writeNew(markerName, append(data, '\n'), replace, 0600); err != nil {
		return refused("cannot write the ownership marker: %s", osReason(err))
	}
	return nil
}

func (s *stateDirectory) inputs(lane string, create bool) (*directory, error) {
	current := s.dir
	for _, name := range []string{"lanes", lane, "inputs"} {
		child, err := current.child(name, create)
		if current != s.dir {
			current.close()
		}
		if err != nil {
			return nil, err
		}
		current = child
	}
	return current, nil
}

func (s *stateDirectory) keep(lane string, data []byte) (string, string, bool, error) {
	hash := digest(data)
	relative := "lanes/" + lane + "/inputs/" + hash
	d, err := s.inputs(lane, true)
	if err != nil {
		return "", "", false, err
	}
	defer d.close()
	info, err := d.fileInfo(hash)
	if err != nil {
		return "", "", false, refused("cannot inspect a kept input")
	}
	if info != nil {
		kept, err := d.read(hash, maxInputBytes, relative)
		if err != nil {
			return "", "", false, err
		}
		if digest(kept) != hash {
			return "", "", false, integrity("kept input %s does not match its hash", relative)
		}
		return relative, hash, false, nil
	}
	if err := d.writeNew(hash, data, false, 0600); err != nil {
		return "", "", false, refused("cannot keep a consumed input: %s", osReason(err))
	}
	return relative, hash, true, nil
}

func (s *stateDirectory) readInput(lane, hash string) ([]byte, error) {
	d, err := s.inputs(lane, false)
	if err != nil {
		return nil, err
	}
	defer d.close()
	return d.read(hash, maxInputBytes, "lanes/"+lane+"/inputs/"+hash)
}
func (s *stateDirectory) removeInput(lane, hash string) error {
	d, err := s.inputs(lane, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer d.close()
	err = d.root.Remove(hash)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
