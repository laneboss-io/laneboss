package orgrender

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"laneboss.io/laneboss/internal/v2/templates"
)

type Input struct {
	Sources []string
	Derived []string
}

// RenderTree renders the opened staged source tree. Task placeholders stay in
// role templates until launch; org imports are expanded now, before approval.
func RenderTree(ctx context.Context, root, inputPath string) error {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	var input Input
	if err := json.Unmarshal(raw, &input); err != nil {
		return err
	}
	sort.Strings(input.Sources)
	files := map[string][]byte{}
	modes := map[string]uint32{}
	type entry struct {
		Path   string
		Mode   uint32
		SHA256 string
		Bytes  int
	}
	inventory := []entry{}
	for _, name := range input.Sources {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		inventory = append(inventory, entry{Path: name, Mode: uint32(info.Mode().Perm()), SHA256: hex.EncodeToString(sum[:]), Bytes: len(data)})
		files[name] = data
		modes[name] = uint32(info.Mode().Perm())
	}
	for _, name := range input.Derived {
		if _, source := files[name]; source {
			continue
		}
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(name))); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	var expand func(string, map[string]bool, map[string]bool) ([]byte, error)
	expand = func(name string, active, emitted map[string]bool) ([]byte, error) {
		if active[name] {
			return nil, fmt.Errorf("org import cycle at %s", name)
		}
		if emitted != nil && emitted[name] {
			return nil, nil
		}
		data, exists := files[name]
		if !exists {
			return nil, fmt.Errorf("org import source is absent: %s", name)
		}
		active[name] = true
		if emitted != nil {
			emitted[name] = true
		}
		defer delete(active, name)
		var text strings.Builder
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "@") && !strings.ContainsAny(line, " \t") {
				target := path.Clean(path.Join(path.Dir(name), strings.TrimPrefix(line, "@")))
				if _, found := files[target]; found {
					included, err := expand(target, active, emitted)
					if err != nil {
						return nil, err
					}
					text.Write(included)
					continue
				}
			}
			text.WriteString(line + "\n")
		}
		return []byte(text.String()), nil
	}
	write := func(name string, data []byte, mode uint32) error {
		if _, source := files[name]; source {
			return nil // A declared source is never a generated destination.
		}
		name = filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			return err
		}
		return os.WriteFile(name, data, os.FileMode(mode))
	}
	for _, name := range input.Sources {
		local := strings.TrimPrefix(name, ".laneboss/")
		asset := strings.HasPrefix(local, "plugins/") || strings.HasPrefix(local, "shared/hooks/")
		markdown := strings.HasSuffix(name, ".md")
		if !markdown && !asset {
			continue
		}
		text := files[name]
		if markdown {
			var err error
			text, err = expand(name, map[string]bool{}, nil)
			if err != nil {
				return err
			}
		}
		mode := uint32(0600)
		if asset {
			mode = modes[name]
		}
		if err := write("rendered/"+local, text, mode); err != nil {
			return err
		}
		// These approved source forms produce the vendor files consumed by
		// private-home seeding. Rendering preserves settings; it does not
		// invent a hook registration or report a plugin as loaded.
		destination := ""
		switch local {
		case "shared/hooks/claude.json":
			destination = "rendered/.claude/settings.json"
		case "shared/hooks/codex.json":
			destination = "rendered/.codex/hooks.json"
		}
		if destination != "" {
			if !json.Valid(text) {
				return fmt.Errorf("hook settings source is invalid JSON: %s", name)
			}
			if err := write(destination, text, mode); err != nil {
				return err
			}
		}
	}
	var shared strings.Builder
	roots := []string{}
	if _, present := files[templates.OrgTemplatePath]; present {
		roots = append(roots, templates.OrgTemplatePath)
	}
	for _, name := range input.Sources {
		if strings.HasSuffix(name, ".md") && strings.Contains(name, "/shared/protocol/") {
			roots = append(roots, name)
		}
	}
	emitted := map[string]bool{}
	for _, name := range roots {
		text, err := expand(name, map[string]bool{}, emitted)
		if err != nil {
			return err
		}
		if len(text) != 0 {
			shared.WriteString("<!-- Source: " + name + " -->\n")
			shared.Write(text)
		}
	}
	if shared.Len() != 0 {
		for _, name := range []string{"AGENTS.md", "CLAUDE.md"} {
			if err := write(name, []byte(shared.String()), 0600); err != nil {
				return err
			}
		}
	}
	raw, err = json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return err
	}
	return write("rendered/inventory.json", append(raw, '\n'), 0600)
}
