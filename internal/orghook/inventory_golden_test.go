package orghook

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Reviewed independently of the grammar walker. Changes require an explicit
// review of the CLI's file effects, including reclassification of old operands.
const grammarPathGolden = `brief render|--in|read
brief render|--out|write
decisions add|--db|read,write,sqlite
decisions add|--file|read
decisions annotate|--db|read,write,sqlite
decisions annotate|--file|read
decisions egress|--db|read,write,sqlite
decisions embed|--db|read,write,sqlite
decisions export|--db|read,write,sqlite
decisions export|--out|write
decisions feedback|--db|read,write,sqlite
decisions get|--db|read,write,sqlite
decisions import|--db|read,write,sqlite
decisions import|--in|read
decisions init|--db|read,write,sqlite
decisions load|--db|read,write,sqlite
decisions load|--in|read
decisions migrate|--db|read,write,sqlite
decisions search|--db|read,write,sqlite
decisions stats|--db|read,write,sqlite
decisions supersede|--db|read,write,sqlite
decisions supersede|--file|read
decisions verify|--db|read,write,sqlite
event append|--file|read
init|--project|read,write
judge ask|--prompt-file|read
judge ask|--subject|read,named
lane adopt|--brief|read
lane adopt|--worktree|read,write
lane archive|--to|write
lane resume|--message|read
lane review|--note|read
lane review|--path|metadata
lane send|--file|read
lane start|--brief|read
lane start|--worktree|read,write
org capture-decision|--instance|read,selector
org capture-decision|--org-dir|read,org-history:capture
org capture-decision|--text-file|read
org channel add|org_dir|read,write
org channel read|org_dir|read
org check-hooks|org|read
org hook-history|--instance|read,selector
org hook-history|--org-dir|read,org-history:inject
org hook|--instance|read
org init|org_dir|read,write
org instance add|org_dir|read,write
org refusals|org|read
org render|org_dir|read,write
org roles init|org_dir|read,write
org roles list|org_dir|read
org validate|org_dir|read
report|--file|read
start|--ticket-file|read
store record|--file|read`

func pathEffectTuple(path []string, argument hookArgument) string {
	effect := argument.Path
	labels := []string{}
	for _, item := range []struct {
		name string
		set  bool
	}{{"read", effect.Read}, {"write", effect.Write}, {"sqlite", effect.SQLite}, {"named", effect.Named}, {"selector", effect.Selector}, {"metadata", effect.Metadata}} {
		if item.set {
			labels = append(labels, item.name)
		}
	}
	if effect.OrgHistory != "" {
		labels = append(labels, "org-history:"+effect.OrgHistory)
	}
	return strings.Join(path, " ") + "|" + argument.Name + "|" + strings.Join(labels, ",")
}

func checkGrammarPathGolden(t *testing.T) {
	t.Helper()
	want := strings.Split(grammarPathGolden, "\n")
	if !sort.StringsAreSorted(want) {
		t.Fatal("the reviewed path golden must remain sorted")
	}
	got := []string{}
	var walk func(*hookSyntax, []string)
	walk = func(node *hookSyntax, path []string) {
		for _, argument := range node.Args {
			if argument.Path != nil {
				got = append(got, pathEffectTuple(path, argument))
			}
		}
		for index := range node.Commands {
			child := &node.Commands[index]
			walk(child, append(append([]string{}, path...), child.Name))
		}
	}
	walk(lanebossSyntax.root, nil)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("path inventory drifted; review additions, deletions and effect changes:\ngot:\n%s\nwant:\n%s", strings.Join(got, "\n"), grammarPathGolden)
	}
}

func TestGrammarPathMetavars(t *testing.T) {
	compatibilitySyntax(t)
	checkGrammarPathGolden(t)
	// Includes compound and legacy path spellings; DB is reserved for future
	// grammar changes even though today's DB operands use FILE.
	pathMetavars := strings.Fields("FILE PATH DIR ORG_DIR ORG-DIR BRIEF DB RENDERED ORG FILE|- NAME=FILE")
	// Reviewed from the CLI's file consumers independently of hook_path and
	// metavar. In particular, decisions export --out has no metavar. Include
	// ambiguous identifiers too, so they need an explicit source justification.
	pathNames := strings.Fields("--out --in --db --file --to --project --worktree --brief --message --note --path --org-dir --instance --text-file --prompt-file --subject --ticket-file --config --judge --touches --set --event --source org_dir org")
	// --config always selects a named configuration. The common loader
	// validates a safe name before joining fixed roots:
	// internal/config/config.go:137, internal/config/load.go:97. A future
	// path-shaped metavar needs its own command-specific review instead.
	notPathNames := map[string]string{"--config": "validated configuration name"}
	notPaths := map[string]string{
		"init|org": "configuration name, validated before joining the fixed configs/orgs roots (internal/bootstrap/init.go:106)",
		// Project operands here are fixed-map keys, never explicit paths:
		// internal/brief/brief.go:246, internal/lane/lifecycle.go:253,
		// internal/laneturns/adopt.go:267. Search compares stored metadata at
		// internal/decisions/search.go:108.
		"brief render|--project":     "loaded project-table key",
		"lane start|--project":       "loaded project-table key",
		"lane adopt|--project":       "loaded project-table key",
		"decisions search|--project": "stored project filter",
		// internal/lane/settings.go:18 calls settings.Instance; that method
		// rejects separators/dot-only names before its fixed-file read at
		// internal/settings/settings.go:451-463. Search only compares a record
		// identity at internal/decisions/search.go:65.
		"lane start|--instance":       "safe identity selecting fixed org policy",
		"decisions search|--instance": "stored instance filter",
		// --to is an alias for a timestamp bound, not an archive destination:
		// internal/decisions/decisions.go:72, internal/decisions/search.go:138.
		"decisions search|--date-to": "date filter (including --to alias)",
		// --touches selects required brief sections and only accepts billing
		// or deploy: internal/brief/sections.go:171, internal/lane/brief.go:150.
		"brief render|--touches": "brief section selector",
		"lane start|--touches":   "brief section selector",
		// --set is parsed as a documented typed setting, with no file-valued
		// key: internal/settings/settings.go:27 and :287.
		"lane start|--set": "typed settings data, not a source-file operand",
		// --event is an enum at internal/decisionsrv/history.go:113. Feedback
		// events/sources become stored metadata, validated without opening
		// either argument: internal/decisions/store.go:878.
		"org hook-history|--event":    "hook event enum",
		"decisions feedback|--event":  "stored feedback event enum",
		"decisions feedback|--source": "stored feedback provenance text",
		// --source is provenance text. sourceTime parses it as a timestamp;
		// its Stat fallback receives --text-file, not --source:
		// internal/decisionsrv/capture.go:28 and :435.
		"org capture-decision|--source": "message provenance and timestamp text",
		// --judge is a loaded configuration-table key; it is never opened:
		// internal/judge/judge.go:174-177, internal/decisionsrv/capture.go:459.
		"judge ask|--judge":            "configured judge name",
		"org capture-decision|--judge": "configured judge name",
		// Positional config names follow GuardNamed then Load, just like
		// --config: internal/config/config.go:414 and :137.
		"config path|name":     "validated configuration name",
		"config show|name":     "validated configuration name",
		"config validate|name": "validated configuration name",
	}
	golden := map[string]bool{}
	for _, tuple := range strings.Split(grammarPathGolden, "\n") {
		parts := strings.Split(tuple, "|")
		golden[parts[0]+"|"+parts[1]] = true
	}
	used := map[string]bool{}
	usedNames := map[string]bool{}
	var walk func(*hookSyntax, []string)
	walk = func(node *hookSyntax, path []string) {
		for _, argument := range node.Args {
			key := strings.Join(path, " ") + "|" + argument.Name
			reason := notPaths[key]
			if reason == "" && !contains(pathMetavars, argument.Metavar) {
				reason = notPathNames[argument.Name]
				if reason != "" {
					usedNames[argument.Name] = true
				}
			}
			if reason != "" {
				if argument.Path != nil {
					t.Fatalf("invalid not-a-path exception: %s", key)
				}
				if notPaths[key] != "" {
					used[key] = true
				}
			}
			pathShaped := contains(pathMetavars, argument.Metavar) || contains(pathNames, argument.Name)
			for _, alias := range argument.Aliases {
				pathShaped = pathShaped || contains(pathNames, alias)
			}
			if pathShaped && !golden[key] && reason == "" {
				t.Errorf("path name/metavar %q/%q lacks a golden effect or a reason: %s", argument.Name, argument.Metavar, key)
			}
		}
		for index := range node.Commands {
			child := &node.Commands[index]
			walk(child, append(append([]string{}, path...), child.Name))
		}
	}
	walk(lanebossSyntax.root, nil)
	if len(used) != len(notPaths) || len(usedNames) != len(notPathNames) {
		t.Fatal("stale not-a-path exception")
	}
}
