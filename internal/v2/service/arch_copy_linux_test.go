//go:build linux

package service

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Follow the real local imports of every supported focused test package,
// including external-package tests. Imported dependencies contribute production
// imports only. Read whole package roots so their embedded assets travel too.
func archiveCopyMissing(repo string, roots []string) ([]string, error) {
	const module = "laneboss.io/laneboss/"
	top := map[string]bool{"internal/v2/admin": true, "internal/v2/cli": true, "internal/v2/service": true, "internal/v2/store": true}
	queue := []string{"internal/v2/admin", "internal/v2/cli", "internal/v2/service", "internal/v2/store"}
	seen := make(map[string]bool)
	var missing []string
	for len(queue) != 0 {
		pkg := queue[0]
		queue = queue[1:]
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		covered := false
		for _, root := range roots {
			covered = covered || pkg == root || strings.HasPrefix(pkg, root+"/")
		}
		if !covered {
			missing = append(missing, pkg)
			continue
		}
		entries, err := os.ReadDir(filepath.Join(repo, filepath.FromSlash(pkg)))
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || strings.HasSuffix(name, "_test.go") && !top[pkg] {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(repo, filepath.FromSlash(pkg), name), nil, parser.ImportsOnly)
			if err != nil {
				return nil, err
			}
			for _, spec := range file.Imports {
				path, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					return nil, err
				}
				if strings.HasPrefix(path, module) {
					queue = append(queue, strings.TrimPrefix(path, module))
				}
			}
		}
	}
	sort.Strings(missing)
	return missing, nil
}

func TestArchiveCopyInputs(t *testing.T) {
	repo, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for depth := 0; depth < 5; depth++ {
		if _, err := os.Stat(filepath.Join(repo, "go.mod")); err == nil {
			break
		}
		repo = filepath.Dir(repo)
	}
	raw, err := os.ReadFile(filepath.Join(repo, "e2e/v2/cases/admin/mutate.py"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start, end := strings.Index(text, "ROOTS = ("), strings.Index(text, "\nOWNED =")
	if start < 0 || end <= start {
		t.Fatal("mutation runner has no inspectable copied roots")
	}
	var roots []string
	for _, match := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(text[start:end], -1) {
		roots = append(roots, match[1])
	}
	missing, err := archiveCopyMissing(repo, roots)
	if err != nil || len(missing) != 0 {
		t.Fatalf("acceptance: focused test copy omits its actual dependency closure: missing=%v err=%v", missing, err)
	}
	// The deciding negative removes a real imported module root. It cannot
	// pass if the closure checker ignores its inputs or returns empty success.
	var withoutMatrix []string
	for _, root := range roots {
		if root != "migration/v2" {
			withoutMatrix = append(withoutMatrix, root)
		}
	}
	missing, err = archiveCopyMissing(repo, withoutMatrix)
	if err != nil || len(missing) != 1 || missing[0] != "migration/v2" {
		t.Fatalf("acceptance: copied-input check missed an actual omitted dependency: missing=%v err=%v", missing, err)
	}
}
