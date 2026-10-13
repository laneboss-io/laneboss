package orghook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// One source supplies both seed policy and its descriptions. None of these ids have special
// meaning in the evaluator: custom orgs use the same schema and ordered evaluation.
var sharedExamples = []map[string]any{
	{"id": "instance-tools", "kind": "tool-allowlist", "tools": []string{"{allowed_tools}"},
		"refuses":          "Tools outside the instance's declared allowlist.",
		"why":              "Each identity receives only the tools its role needs.",
		"instead":          "Use an allowed tool or ask the supervisor to change the instance policy.",
		"examples_allowed": []string{"Use Read when Read is listed in allowed_tools."}, "examples_refused": []string{"Use an unlisted tool."}},
	{"id": "declared-writes", "kind": "write-scope", "paths": []string{"{writable_repos}"}, "deny_paths": []string{"{hook_paths}"},
		"refuses":          "Writes outside declared repositories, writes to hook policy and settings, and uninspectable commands.",
		"why":              "An agent's writes must stay in its scope and cannot change the guard that enforces it.",
		"instead":          "Write in a declared repository with a supported file tool; leave policy changes to the supervisor.",
		"examples_allowed": []string{"Edit a source file inside a declared writable repository."}, "examples_refused": []string{"Write in another identity's repository.", "Replace shared/hooks/rules.toml."}},
	{"id": "secret-files", "kind": "secret-read", "names": []string{"{secret_names}", ".env", ".env.*", "*.key", "*.pem"},
		"refuses":          "Reading or printing a file whose name is protected as a secret.",
		"why":              "Secret values must remain outside agent output at every level.",
		"instead":          "Refer to a secret by name and use the configured credential service without printing its value.",
		"examples_allowed": []string{"Read README.md.", "Print the literal name of a secret without reading its file."}, "examples_refused": []string{"Read .env.", "Print a file listed in secret_names."}},
	{"id": "runner-launches", "kind": "command-pattern", "patterns": [][]string{{"claude"}, {"codex"}},
		"refuses":          "Starting an agent runner directly from an agent tool call.",
		"why":              "The launcher must check and pass the org's mandatory hook settings before a runner starts.",
		"instead":          "Have the supervisor start the instance through the checked launcher command.",
		"examples_allowed": []string{"Run git status."}, "examples_refused": []string{"Start claude directly.", "Start codex directly."}},
}

var worktreeExample = map[string]any{
	"id": "worktree-writes", "kind": "write-scope", "paths": []string{"{worktree}"},
	"refuses": "Writing outside the executor's own worktree.", "why": "Executor work must stay isolated from other lanes and repositories.",
	"instead":          "Make the change in this instance's worktree and report it for review.",
	"examples_allowed": []string{"Write a source file in this instance's worktree."}, "examples_refused": []string{"Write to a sibling worktree."},
}
var noPushExample = map[string]any{
	"id": "no-push", "kind": "command-pattern", "patterns": [][]string{{"git", "push"}},
	"refuses": "Pushing repository changes from an executor or mini-supervisor.", "why": "Publishing changes belongs to the supervising level.",
	"instead":          "Leave the changes for review and ask the supervisor to publish them.",
	"examples_allowed": []string{"git status", "printf '%s' 'git push'"}, "examples_refused": []string{"git push", "git -C repository push origin topic"},
}
var supervisorExample = map[string]any{
	"id": "supervisor-writes", "kind": "write-scope", "paths": []string{"{writable_repos}"},
	"refuses": "Writing outside the supervisor identity's declared repositories.", "why": "A supervising level does not grant access to another identity's repositories.",
	"instead":          "Use a declared repository or ask for a policy change before writing elsewhere.",
	"examples_allowed": []string{"Edit a file in a repository listed in writable_repos."}, "examples_refused": []string{"Edit a file in an undeclared repository."},
}
var descriptionKeys = []string{"id", "refuses", "why", "instead", "examples_allowed", "examples_refused"}

func exampleFiles(levels []int) (map[string]string, error) {
	seen := map[int]bool{}
	if len(levels) == 0 {
		return nil, invalid("example hook levels must be distinct integers from 3 to 6")
	}
	for _, level := range levels {
		if !allowedLevel(level) || seen[level] {
			return nil, invalid("example hook levels must be distinct integers from 3 to 6")
		}
		seen[level] = true
	}
	type layer struct {
		name    string
		entries []map[string]any
		levels  []int
	}
	layers := []layer{{"shared", sharedExamples, levels}}
	for _, level := range levels {
		entries := []map[string]any{supervisorExample}
		if level == 3 {
			entries = []map[string]any{worktreeExample, noPushExample}
		} else if level == 4 {
			entries = []map[string]any{noPushExample}
		}
		layers = append(layers, layer{fmt.Sprintf("L%d", level), entries, []int{level}})
	}
	files := map[string]string{}
	for _, layer := range layers {
		var rules strings.Builder
		rules.WriteString("schema_version = 1\n")
		for _, entry := range layer.entries {
			rules.WriteString("\n[[rules]]\n")
			for _, key := range sortedKeys(entry) {
				if contains(descriptionKeys, key) && key != "id" {
					continue
				}
				value, err := json.Marshal(entry[key])
				if err != nil {
					return nil, invalid("example policy cannot be encoded")
				}
				rules.WriteString(key + " = " + string(value) + "\n")
			}
			var description strings.Builder
			for _, key := range descriptionKeys {
				value, err := json.Marshal(entry[key])
				if err != nil {
					return nil, invalid("example refusal cannot be encoded")
				}
				description.WriteString(key + " = " + string(value) + "\n")
			}
			applicable, err := json.Marshal(layer.levels)
			if err != nil {
				return nil, invalid("example levels cannot be encoded")
			}
			description.WriteString("\n[applies_to]\nlevels = " + string(applicable) + "\nidentities = [\"*\"]\n")
			files[layer.name+"/refusals/"+entry["id"].(string)+".toml"] = description.String()
		}
		files[layer.name+"/hooks/rules.toml"] = rules.String()
	}
	return files, nil
}

// SeedHookRules writes generic rules and refusal descriptions and never overwrites existing policy.
func SeedHookRules(org string, levels []int) error {
	files, err := exampleFiles(levels)
	if err != nil {
		return err
	}
	home, err := orgHome(org)
	if err != nil {
		return err
	}
	missing := []generatedFile{}
	for _, relative := range sortedFiles(files) {
		path := filepath.Join(home, filepath.FromSlash(relative))
		if _, err := os.Lstat(path); err == nil {
			if isSymlink(path) || !regular(path) {
				return invalid("an existing policy file must be regular and may not be a symlink")
			}
			continue
		} else if !os.IsNotExist(err) {
			return invalid("an existing policy file is unreadable")
		}
		if err := safeGeneratedPath(path); err != nil {
			return err
		}
		missing = append(missing, generatedFile{path, []byte(files[relative])})
	}
	for _, file := range missing {
		if err := writeGenerated(file.path, file.data); err != nil {
			return err
		}
	}
	return nil
}
