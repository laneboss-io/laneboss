package orghook

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func compoundEffects(commands []command) (reads, writes, metadata []string, opaque bool) {
	collect := func(values []string) []string {
		seen := map[string]bool{}
		for _, value := range values {
			seen[value] = true
		}
		result := []string{}
		for value := range seen {
			result = append(result, value)
		}
		sort.Strings(result)
		return result
	}
	for _, cmd := range commands {
		reads, writes, metadata = append(reads, cmd.reads...), append(writes, cmd.writes...), append(metadata, cmd.metadata...)
		opaque = opaque || cmd.opaque
	}
	return collect(reads), collect(writes), collect(metadata), opaque
}

func TestCompoundBranches(t *testing.T) {
	script := "if [ -f /fixture/first ]; then cat /fixture/first; elif test -d /fixture/folder; then head -n 1 /fixture/second; else touch /fixture/out; fi"
	commands, err := inspectShell(script, "/fixture", 0)
	if err != nil {
		t.Fatal(err)
	}
	reads, writes, metadata, opaque := compoundEffects(commands)
	if opaque || !reflect.DeepEqual(reads, []string{"/fixture/first", "/fixture/second"}) ||
		!reflect.DeepEqual(writes, []string{"/fixture/out"}) || !reflect.DeepEqual(metadata, []string{"/fixture/first", "/fixture/folder"}) {
		t.Fatal("every compound arm must retain content, metadata and write effects")
	}
}

func TestCompoundLiterals(t *testing.T) {
	for _, script := range []string{"[ -f /fixture/read ] && cat /fixture/read", "test -d /fixture/folder || ls /fixture/folder",
		"if [[ -f /fixture/read && -r /fixture/read ]]; then cat /fixture/read; else true; fi",
		"if ! false\nthen\ncat /fixture/read\nfi", "printf '%s' 'if'; true", "if test -z ''; then printf '%s' ''; else false; fi"} {
		commands, err := inspectShell(script, "/fixture", 0)
		if err != nil {
			t.Fatal("literal compounds must remain inspectable")
		}
		if _, _, _, opaque := compoundEffects(commands); opaque {
			t.Fatal("literal compounds must retain known simple commands")
		}
	}
	for _, branch := range []string{"cat $INPUT", "cat $(helper)", "cat `helper`", "echo *.txt", "cat /fixture/read | unknown-helper",
		"(cat /fixture/read)", "for x in a; do true; done", "reader() { true; }", "cat <<EOF\nx\nEOF\n", "[[ unknown -eq 1 ]]"} {
		commands, err := inspectShell("if true; then true; else "+branch+"; fi", "/fixture", 0)
		if _, _, _, opaque := compoundEffects(commands); err == nil && !opaque {
			t.Fatal("an unsupported branch must never become inspectable")
		}
	}
	tooDeep := strings.Repeat("if true; then ", 34) + "true; " + strings.Repeat("fi; ", 34)
	if _, err := inspectShell(tooDeep, "/fixture", 0); err == nil {
		t.Fatal("compound nesting must remain bounded")
	}
}

func TestResolvedShellState(t *testing.T) {
	for _, prefix := range []string{"", "builtin ", "command ", "exec ", "env ", "LB_CANARY=literal ", "LB_CANARY=literal builtin ", "env LB_CANARY=literal "} {
		for _, name := range []string{"cd", "pushd", "popd", "dirs", "export", "set", "shopt", "setopt", "alias", "unalias", "eval", "source", "."} {
			words, err := splitWords(prefix + name + " /fixture")
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := resolveShellCommand(words)
			if err != nil || resolved.name != name || !resolved.changesState {
				t.Fatal("wrappers and assignments must retain the effective command state")
			}
			if _, err := inspectShell("if true; then "+prefix+name+" /fixture; else true; fi", "/fixture", 0); err == nil {
				t.Fatal("compound state changes must refuse after command resolution")
			}
		}
	}
	for _, arguments := range [][]string{{"-v", "LB_CANARY", "%s", "literal"}, {"%n", "LB_CANARY"}, {"--", "%5n", "LB_CANARY"}} {
		if !printfState(arguments) {
			t.Fatal("printf variable assignments must retain state effects")
		}
	}
	for _, arguments := range [][]string{{"%s", "literal"}, {"%%n"}, {"%sn", "literal"}} {
		if printfState(arguments) {
			t.Fatal("ordinary printf output must not become a variable assignment")
		}
	}
}
