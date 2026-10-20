package manifest

import (
	"path"
	"strings"
	"unicode"

	"laneboss.io/laneboss/internal/v2/api"
)

const MaxEntries = 100000

// Object validates a byte-defined tree. Host files, hardlinks and mount aliases
// have no representation here; broker volumes require a separate pinned lease.
func Object(value api.ObjectManifest) error {
	return objectTree(value, false)
}

// Archived validates inert archive data, including original special bits and
// Git names. The ordinary Object validator keeps its stricter import policy.
func Archived(value api.ObjectManifest) error {
	return objectTree(value, true)
}

func objectTree(value api.ObjectManifest, archived bool) error {
	if value.Schema != "laneboss.objects.v2" || value.Entries == nil || len(value.Entries) > MaxEntries {
		return Invalid("invalid object manifest schema or entries")
	}
	if value.Git != nil && (!GitHead(value.Git.Head) || Relative(value.Git.Branch) != nil) {
		return Invalid("invalid archived Git head or branch")
	}
	entries := make(map[string]api.ObjectEntry, len(value.Entries))
	for _, entry := range value.Entries {
		if err := relativeName(entry.Path, archived); err != nil {
			return err
		}
		if _, duplicate := entries[entry.Path]; duplicate {
			return Invalid("duplicate object path")
		}
		allowedMode := uint32(0777)
		if archived {
			allowedMode = 07777
		}
		if entry.Mode & ^allowedMode != 0 {
			return Invalid("object mode contains special permission bits")
		}
		if entry.Path == "." && entry.Kind != "directory" {
			return Invalid("the object root must be a directory")
		}
		switch entry.Kind {
		case "file":
			if (entry.Content == nil) == (entry.Assembly == nil) || entry.LinkTarget != "" {
				return Invalid("file needs exactly one content reference or assembly and no link target")
			}
			if entry.Content != nil {
				if err := Blob(*entry.Content); err != nil {
					return err
				}
				if entry.Content.Class != "artifact" {
					return Invalid("data file content must be an artifact object")
				}
			} else if err := Assembly(*entry.Assembly); err != nil {
				return err
			}
		case "directory":
			if entry.Content != nil || entry.Assembly != nil || entry.LinkTarget != "" {
				return Invalid("directory cannot contain file or link metadata")
			}
		case "symlink":
			if entry.Path == "." || entry.Content != nil || entry.Assembly != nil || entry.LinkTarget == "" ||
				strings.HasPrefix(entry.LinkTarget, "/") ||
				strings.ContainsAny(entry.LinkTarget, "\\\x00\r\n") || len(entry.LinkTarget) > 4096 {
				return Invalid("symlink must have an internal relative target")
			}
		default:
			return Invalid("object kind must be file, directory or symlink")
		}
		entries[entry.Path] = entry
	}
	for name := range entries {
		for parent := path.Dir(name); name != "."; parent = path.Dir(parent) {
			if parentEntry, found := entries[parent]; found && parentEntry.Kind != "directory" {
				return Invalid("object has a non-directory parent or alias")
			}
			if parent == "." {
				break
			}
		}
	}
	if err := addDirectories(entries); err != nil {
		return err
	}
	folded := map[string]string{}
	for name := range entries {
		key := strings.Map(foldRune, name)
		if prior, found := folded[key]; found && prior != name {
			return Invalid("object paths collide under filesystem case folding")
		}
		folded[key] = name
	}
	for name, entry := range entries {
		if entry.Kind == "symlink" {
			if _, err := resolveTree(entries, name, ".", archived); err != nil {
				return err
			}
		}
	}
	return treeCycles(entries, archived)
}

func GitHead(head string) bool {
	if len(head) != 40 && len(head) != 64 {
		return false
	}
	for _, c := range head {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func foldRune(value rune) rune {
	least := value
	for next := unicode.SimpleFold(value); next != value; next = unicode.SimpleFold(next) {
		if next < least {
			least = next
		}
	}
	return least
}

func directoryCycles(entries map[string]api.ObjectEntry) error {
	return treeCycles(entries, false)
}

func treeCycles(entries map[string]api.ObjectEntry, archived bool) error {
	edges := map[string][]string{}
	for name, entry := range entries {
		if entry.Kind == "directory" && name != "." {
			edges[path.Dir(name)] = append(edges[path.Dir(name)], name)
		}
		if entry.Kind == "symlink" {
			target, err := resolveTree(entries, name, ".", archived)
			if err != nil {
				return err
			}
			if entries[target].Kind == "directory" {
				edges[path.Dir(name)] = append(edges[path.Dir(name)], target)
			}
		}
	}
	states := map[string]uint8{}
	var visit func(string) error
	visit = func(name string) error {
		if states[name] == 1 {
			return Invalid("directory symlinks form a cycle")
		}
		if states[name] == 2 {
			return nil
		}
		states[name] = 1
		for _, target := range edges[name] {
			if err := visit(target); err != nil {
				return err
			}
		}
		states[name] = 2
		return nil
	}
	return visit(".")
}

// Assembly describes a large file as ordinary bounded immutable objects.
// Its concatenated byte digest is checked separately when consuming the parts.
func Assembly(value api.ObjectAssembly) error {
	if !ValidDigest(value.SHA256) || value.Bytes <= api.MaxObjectBytes ||
		uint64(value.Bytes) > MaxInteger || len(value.Parts) < 2 || len(value.Parts) > MaxEntries {
		return Invalid("invalid large-file assembly digest, size or parts")
	}
	var total int64
	for _, part := range value.Parts {
		if err := Blob(part); err != nil {
			return err
		}
		if part.Class != "artifact" || part.Bytes == 0 || part.Bytes > value.Bytes-total {
			return Invalid("assembly parts must be bounded artifacts within the declared size")
		}
		total += part.Bytes
	}
	if total != value.Bytes {
		return Invalid("assembly part sizes differ from the declared file size")
	}
	return nil
}

// ContentRefs includes every part, in assembly order. It grants no authority.
func ContentRefs(entry api.ObjectEntry) []api.BlobRef {
	if entry.Content != nil {
		return []api.BlobRef{*entry.Content}
	}
	if entry.Assembly != nil {
		return entry.Assembly.Parts
	}
	return nil
}

// Select checks the exact source view before a grant can be released. Selecting
// a link itself is refused: an alias cannot silently change the requested root.
// Links beneath a directory must remain inside that directory after resolution.
func Select(value api.ObjectManifest, relative string) ([]api.ObjectEntry, error) {
	return selectEntries(value, relative, false)
}

func SelectArchive(value api.ObjectManifest, relative string) ([]api.ObjectEntry, error) {
	return selectEntries(value, relative, true)
}

func selectEntries(value api.ObjectManifest, relative string, archived bool) ([]api.ObjectEntry, error) {
	if err := objectTree(value, archived); err != nil {
		return nil, err
	}
	if err := Relative(relative); err != nil {
		return nil, err
	}
	entries := make(map[string]api.ObjectEntry, len(value.Entries))
	for _, entry := range value.Entries {
		entries[entry.Path] = entry
	}
	if err := addDirectories(entries); err != nil {
		return nil, err
	}
	resolved, err := resolveTree(entries, relative, ".", archived)
	if err != nil {
		return nil, err
	}
	if resolved != relative {
		return nil, Invalid("source selection must name an object, not a symlink alias")
	}
	selected := []api.ObjectEntry{}
	for _, entry := range value.Entries {
		if !Beneath(relative, entry.Path) {
			continue
		}
		if entry.Kind == "symlink" {
			target, err := resolveTree(entries, entry.Path, relative, archived)
			if err != nil {
				return nil, err
			}
			if !Beneath(relative, target) {
				return nil, Invalid("selected symlink reaches outside the granted subtree")
			}
		}
		selected = append(selected, entry)
	}
	return selected, nil
}

func resolve(entries map[string]api.ObjectEntry, name, root string) (string, error) {
	return resolveTree(entries, name, root, false)
}

func resolveTree(entries map[string]api.ObjectEntry, name, root string, archived bool) (string, error) {
	if name == "." {
		return ".", nil
	}
	pending := strings.Split(name, "/")
	stack := []string{}
	floor := 0
	if root != "." {
		floor = len(strings.Split(root, "/"))
	}
	entered := root == "."
	links := 0
	for len(pending) > 0 {
		component := pending[0]
		pending = pending[1:]
		switch component {
		case ".":
			continue
		case "", "..":
			if component == "" || len(stack) == 0 {
				return "", Invalid("symlink escapes the object root")
			}
			if entered && len(stack) <= floor {
				return "", Invalid("symlink traversal crosses the selected root")
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if err := relativeName(component, archived); err != nil {
			return "", err
		}
		current := strings.Join(append(append([]string{}, stack...), component), "/")
		entry, found := entries[current]
		if found && entry.Kind == "symlink" {
			links++
			if links > 40 {
				return "", Invalid("symlink resolution has a cycle or exceeds its bound")
			}
			pending = append(strings.Split(entry.LinkTarget, "/"), pending...)
			continue
		}
		if found && entry.Kind != "directory" && len(pending) != 0 {
			return "", Invalid("source path traverses a non-directory")
		}
		if !found {
			return "", Invalid("source path or symlink target is absent")
		}
		stack = append(stack, component)
		if strings.Join(stack, "/") == root {
			entered = true
		}
	}
	if len(stack) == 0 {
		return ".", nil
	}
	return strings.Join(stack, "/"), nil
}

func addDirectories(entries map[string]api.ObjectEntry) error {
	// Index implicit directories once, instead of scanning every manifest entry
	// for every component of every symlink or requested path.
	parents := map[string]bool{}
	for name := range entries {
		for parent := path.Dir(name); name != "."; parent = path.Dir(parent) {
			if _, exists := entries[parent]; !exists && !parents[parent] {
				if len(entries)+len(parents) >= MaxEntries {
					return Invalid("object directory index exceeds its bounded size")
				}
				parents[parent] = true
			}
			if parent == "." {
				break
			}
		}
	}
	for parent := range parents {
		if _, found := entries[parent]; !found {
			entries[parent] = api.ObjectEntry{Path: parent, Kind: "directory"}
		}
	}
	return nil
}
