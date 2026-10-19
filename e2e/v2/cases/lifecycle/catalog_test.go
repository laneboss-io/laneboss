package lifecyclecase

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Catalog integrity is a source-level unit check. It does not turn a blocked
// production acceptance row into passing runtime evidence.
func TestMutationCatalog(t *testing.T) {
	var catalog struct {
		Schema    string `json:"schema"`
		Mutations []struct {
			ID            string `json:"id"`
			Rule          string `json:"rule"`
			Status        string `json:"status"`
			File          string `json:"file"`
			Before        string `json:"before"`
			After         string `json:"after"`
			Mode          string `json:"mode"`
			Test          string `json:"test"`
			Expect        string `json:"expect"`
			Mutation      string `json:"mutation"`
			Gaps          []int  `json:"gaps"`
			Reason        string `json:"reason"`
			FixtureMethod string `json:"fixture_method"`
		} `json:"mutations"`
	}
	raw, err := os.ReadFile("mutations.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	if catalog.Schema != "lifecycle.mutations.v1" || len(catalog.Mutations) == 0 {
		t.Fatal("missing versioned lifecycle mutation catalog")
	}
	root := filepath.Join("..", "..", "..", "..")
	names := map[string]bool{}
	guards, blocked := 0, 0
	for _, row := range catalog.Mutations {
		if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,38}$`).MatchString(row.ID) || names[row.ID] ||
			row.Rule == "" || row.Test == "" {
			t.Fatal("invalid mutation identity, rule or named test")
		}
		names[row.ID] = true
		switch row.Status {
		case "blocked":
			blocked++
			if row.Mutation == "" || row.Reason == "" || len(row.Gaps) == 0 {
				t.Fatal("blocked production row lost its mutation or contract dependency")
			}
		case "guard":
			guards++
			path := filepath.FromSlash(row.File)
			parts := strings.Split(row.File, "/")
			fixture := row.FixtureMethod != ""
			if filepath.IsAbs(path) || strings.Contains(row.File, "..") || len(parts) < 2 ||
				strings.HasSuffix(path, "_test.go") != fixture || row.Before == "" || row.Before == row.After || row.Expect == "" {
				t.Fatal("mutation attempted to change a test or an unowned path")
			}
			parent := filepath.ToSlash(filepath.Dir(path))
			if parent != "internal/v2/lifecycle" && row.File != "internal/v2/archive/read.go" && row.File !=
				filepath.ToSlash(filepath.Join("internal", "v2", "cli", "commands_lifecycle.go")) && row.File !=
				filepath.ToSlash(filepath.Join("internal", "v2", "cli", "internal_lifecycle.go")) {
				t.Fatal("mutation escaped lane-owned product files")
			}
			data, err := os.ReadFile(filepath.Join(root, path))
			if err != nil {
				t.Fatal(err)
			}
			if fixture && (!(filepath.Base(path) == "fixtures_test.go" || filepath.Base(path) == "launchfix_test.go" ||
				filepath.Base(path) == "credfix_test.go" || filepath.Base(path) == "failfix_test.go" || strings.HasSuffix(path, "_fixture_test.go")) ||
				row.Mode != "" && row.Mode != "once" || !fixtureMethodAnchor(data, row.FixtureMethod, row.Before)) {
				t.Fatal("fixture control escaped its declared receiver method")
			}
			count := strings.Count(string(data), row.Before)
			if row.Mode == "identifier" {
				if count < 2 {
					t.Fatalf("identifier mutation lost its declaration/references: %s", row.ID)
				}
			} else if row.Mode != "" && row.Mode != "once" || count != 1 {
				t.Errorf("mutation anchor changed or is ambiguous: %s", row.ID)
			}
		default:
			t.Fatal("unknown mutation coverage status")
		}
	}
	if guards == 0 || blocked == 0 {
		t.Fatal("catalog failed to distinguish executable guards and pending production evidence")
	}
}

func fixtureMethodAnchor(data []byte, method, anchor string) bool {
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, "fixture.go", data, 0)
	if err != nil {
		return false
	}
	matches := 0
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if strings.HasPrefix(function.Name.Name, "Test") {
			return false
		}
		if function.Recv != nil && function.Name.Name == method && function.Body != nil {
			start, end := positions.Position(function.Body.Pos()).Offset, positions.Position(function.Body.End()).Offset
			if strings.Count(string(data[start:end]), anchor) == 1 {
				matches++
			}
		}
	}
	return matches == 1
}
