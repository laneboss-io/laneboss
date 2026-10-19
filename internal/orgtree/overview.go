package orgtree

import (
	"os"

	"laneboss.io/laneboss/internal/instancename"
)

// ReadOverview shares the org command's TOML parser, tree file checks and schema
// validators. Only org/instance metadata is read; prompts and credentials are
// never part of the overview.
func ReadOverview(argument string) (map[string]any, error) {
	root, err := rootPath(argument)
	if err != nil {
		return nil, err
	}
	t := newTree(root)
	orgFile := home + "/org.toml"
	t.read(orgFile, true)
	data, _ := t.documents[orgFile].(map[string]any)
	if data != nil {
		t.problems = append(t.problems, checkOrg(data, orgFile, root)...)
	}
	levels, _ := array(data["levels"])
	enabled := []int{}
	for _, value := range levels {
		if n, ok := integer(value); ok {
			enabled = append(enabled, n)
		}
	}
	instances := []any{}
	if t.directory(home+"/instances", "instances directory is missing") {
		entries, e := os.ReadDir(t.filename(home + "/instances"))
		if e != nil {
			t.problem(home+"/instances", "cannot list instances")
		}
		for _, entry := range entries {
			if !instancename.Valid(entry.Name()) {
				t.problem(home+"/instances", "instance directory name must be a simple name")
				continue
			}
			dir := home + "/instances/" + entry.Name()
			if !t.directory(dir, "instance must be a directory") {
				continue
			}
			file := dir + "/instance.toml"
			t.read(file, true)
			instance, _ := t.documents[file].(map[string]any)
			if instance == nil {
				continue
			}
			t.problems = append(t.problems, checkInstance(instance, file, entry.Name(), enabled)...)
			instances = append(instances, map[string]any{"name": instance["name"], "level": instance["level"], "role": instance["role"]})
		}
	}
	if len(t.problems) > 0 {
		return nil, problemsError(t.problems)
	}
	return map[string]any{"name": data["name"], "levels": levels, "instances": instances}, nil
}
