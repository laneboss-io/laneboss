// Package rolepolicy resolves org-owned and embedded roles and enforces their drivers.
package rolepolicy

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

//go:embed library/L*/*.md library/L*/*.toml
var library embed.FS

// Builtin returns a read-only embedded fallback, or nil when the role is not
// shipped at this level. Its paths identify retained embedded bytes, not files
// that callers should create in the org.
func Builtin(level int, name string) (*Template, error) {
	if err := CheckName(name); err != nil {
		return nil, err
	}
	filename := fmt.Sprintf("library/L%d/%s.md", level, name)
	body, err := library.ReadFile(filename)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("the embedded role template cannot be read")
	}
	if err := CheckTemplate(body); err != nil {
		return nil, err
	}
	driverBytes, err := library.ReadFile(strings.TrimSuffix(filename, ".md") + ".toml")
	if err != nil {
		return nil, errors.New("the embedded role needs its TOML driver file")
	}
	drivers, err := parseDrivers(driverBytes)
	if err != nil {
		return nil, err
	}
	rolePath := fmt.Sprintf("builtin/L%d/roles/%s.md", level, name)
	return &Template{Name: name, Path: rolePath, DriverPath: strings.TrimSuffix(rolePath, ".md") + ".toml", Bytes: body, DriverBytes: driverBytes, Drivers: drivers}, nil
}

func builtinTemplates(level int) (map[string]*Template, error) {
	files, err := LibraryFiles([]int{level})
	if err != nil {
		return nil, err
	}
	roles := map[string]*Template{}
	for filename := range files {
		if !strings.HasSuffix(filename, ".md") {
			continue
		}
		name := strings.TrimSuffix(path.Base(filename), ".md")
		role, err := Builtin(level, name)
		if err != nil {
			return nil, err
		}
		roles[name] = role
	}
	return roles, nil
}

// LibraryFiles returns independent copies of the shipped source bytes. Paths
// are relative to .laneboss; installation needs no network or source checkout.
func LibraryFiles(levels []int) (map[string]string, error) {
	files := map[string]string{}
	for _, level := range levels {
		directory := fmt.Sprintf("library/L%d", level)
		entries, err := fs.ReadDir(library, directory)
		if err != nil {
			return nil, fmt.Errorf("the role library has no supported level")
		}
		for _, entry := range entries {
			data, err := library.ReadFile(path.Join(directory, entry.Name()))
			if err != nil {
				return nil, fmt.Errorf("the embedded role library cannot be read")
			}
			files[fmt.Sprintf("L%d/roles/%s", level, entry.Name())] = string(data)
		}
	}
	return files, nil
}

// Library lists every built-in template, including its exact source hash.
func Library() ([]map[string]any, error) {
	files, err := LibraryFiles([]int{3, 4, 5, 6})
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	for _, filename := range sortedKeys(files) {
		if !strings.HasSuffix(filename, ".md") {
			continue
		}
		parts := strings.Split(filename, "/")
		level, err := strconv.Atoi(parts[0][1:])
		if err != nil {
			return nil, fmt.Errorf("the embedded role library has an invalid level")
		}
		drivers, err := parseDrivers([]byte(files[strings.TrimSuffix(filename, ".md")+".toml"]))
		if err != nil {
			return nil, err
		}
		rows = append(rows, map[string]any{"level": level, "role": strings.TrimSuffix(parts[2], ".md"), "drivers": drivers, "sha256": Hash([]byte(files[filename]))})
	}
	return rows, nil
}
