// Package jobcatalog generates hook jobs from the CLI's actual syntax tree and
// the org's source files. The CLI registers its embedded syntax once at startup.
package jobcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

const RelativePath = "shared/services/laneboss-jobs.json"

type node struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Help        string `json:"help"`
	Args        []struct {
		Name string `json:"name"`
	} `json:"args"`
	Commands []node `json:"commands"`
	Group    bool   `json:"subcommand_required"`
}

var syntaxHash string
var jobs, groups []map[string]any
var extra []string

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Register consumes both the unmodified embedded bytes and the CLI's expanded
// root. Commands added by the CLI in code therefore need no second list here.
func Register(syntax, expanded []byte) error {
	var original, root node
	if json.Unmarshal(syntax, &original) != nil || json.Unmarshal(expanded, &root) != nil {
		return errors.New("cannot read embedded job syntax")
	}
	syntaxHash = Digest(syntax)
	jobs, groups, extra = []map[string]any{}, []map[string]any{}, []string{}
	var walk func(node, string)
	walk = func(parent node, prefix string) {
		for _, child := range parent.Commands {
			path := strings.TrimSpace(prefix + " " + child.Name)
			purpose := child.Description
			if purpose == "" {
				purpose = child.Help
			}
			arguments := []string{}
			for _, argument := range child.Args {
				if argument.Name != "--help" && argument.Name != "-h" {
					arguments = append(arguments, argument.Name)
				}
			}
			row := map[string]any{"path": path, "purpose": strings.Join(strings.Fields(purpose), " "), "arguments": arguments}
			if child.Group {
				groups = append(groups, row)
			} else {
				jobs = append(jobs, row)
			}
			walk(child, path)
		}
	}
	walk(root, "")
	known := map[string]bool{}
	for _, child := range original.Commands {
		known[child.Name] = true
	}
	for _, child := range root.Commands {
		if !known[child.Name] {
			extra = append(extra, child.Name)
		}
	}
	if len(jobs) == 0 {
		return errors.New("job catalog needs at least one job")
	}
	return nil
}

func Available() bool { return syntaxHash != "" }

// RoleSource accepts only the editable library inputs, excluding generated
// rules, instance state and service records. Paths are relative to .laneboss.
func RoleSource(path string) bool {
	parts := strings.Split(path, "/")
	return len(parts) == 3 && len(parts[0]) == 2 && parts[0][0] == 'L' && parts[0][1] >= '3' && parts[0][1] <= '6' &&
		parts[1] == "roles" && (strings.HasSuffix(parts[2], ".md") || strings.HasSuffix(parts[2], ".toml"))
}

// Build hashes exact org and role source bytes. The fingerprint includes the
// embedded syntax and generated rows, including commands added in code.
func Build(orgBytes []byte, files map[string]string) (map[string]any, error) {
	if !Available() {
		return nil, errors.New("embedded job syntax is unavailable")
	}
	var org map[string]any
	if _, err := toml.Decode(string(orgBytes), &org); err != nil {
		return nil, errors.New("job catalog cannot read org sources")
	}
	roles, ok := org["roles"].(map[string]any)
	if !ok {
		roles = map[string]any{}
	}
	orgState := map[string]any{"name": org["name"], "levels": org["levels"], "roles": roles}
	if value, exists := org["lane_roles"]; exists {
		orgState["lane_roles"] = value
	}
	hashes := map[string]string{}
	names := []string{}
	for path, text := range files {
		if RoleSource(path) {
			hashes[path] = Digest([]byte(text))
			// Match the generator's level/role order without file extensions.
			names = append(names, strings.TrimSuffix(strings.TrimSuffix(path, ".md"), ".toml"))
		}
	}
	sort.Strings(names)
	library, seen := []map[string]any{}, map[string]bool{}
	for _, path := range names {
		parts := strings.Split(path, "/")
		role := parts[2]
		key := parts[0] + "/" + role
		if !seen[key] {
			library = append(library, map[string]any{"level": int(parts[0][1] - '0'), "role": role})
			seen[key] = true
		}
	}
	if len(library) > 0 {
		orgState["role_library"] = library
	}
	roleBytes, err := json.Marshal(hashes)
	if err != nil {
		return nil, err
	}
	rows, err := json.Marshal(map[string]any{"laneboss_jobs": jobs, "laneboss_groups": groups})
	if err != nil {
		return nil, err
	}
	orgHash, rolesHash, rowsHash := Digest(orgBytes), Digest(roleBytes), Digest(rows)
	fingerprint := Digest([]byte(strings.Join([]string{syntaxHash, orgHash, rolesHash, rowsHash}, "\n")))
	return map[string]any{
		"schema": 1, "org": orgState, "laneboss_jobs": jobs, "laneboss_groups": groups,
		"source": map[string]any{"file": "internal/cli/syntax.json", "sha256": syntaxHash,
			"jobs": len(jobs), "groups": len(groups), "added_in_code": extra,
			"org_sha256": orgHash, "roles_sha256": rolesHash, "rows_sha256": rowsHash, "fingerprint": fingerprint},
	}, nil
}

// Matches checks the full regenerated content as well as the fingerprint, so
// editing a row while leaving its source hashes intact also makes it stale.
func Matches(raw []byte, expected map[string]any) bool {
	var found map[string]any
	if json.Unmarshal(raw, &found) != nil {
		return false
	}
	a, err := json.Marshal(found)
	if err != nil {
		return false
	}
	b, err := json.Marshal(expected)
	return err == nil && string(a) == string(b)
}

func Criteria(state map[string]any) (map[string]string, error) {
	rows, ok := state["laneboss_jobs"].([]map[string]any)
	if !ok || len(rows) == 0 || len(rows)+1 > 255 {
		return nil, errors.New("job catalog has no usable choices")
	}
	criteria := map[string]string{"none": "the shell command does no job that a laneboss command already does"}
	for _, row := range rows {
		path, pathOK := row["path"].(string)
		purpose, purposeOK := row["purpose"].(string)
		if !pathOK || !purposeOK || path == "" || purpose == "" {
			return nil, fmt.Errorf("job catalog has an incomplete row")
		}
		criteria[path] = purpose
	}
	return criteria, nil
}
