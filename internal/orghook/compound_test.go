package orghook

import (
	"path/filepath"
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
			if _, err := inspectShell("if true; then "+prefix+name+" /fixture; else true; fi", "/fixture", 0); err != nil {
				t.Fatal("compound state changes must remain segment-inspectable")
			}
		}
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	commands, err := inspectShell("cd '"+directory+"' && git push origin main", "/", 0)
	if err != nil || len(commands) == 0 || commands[len(commands)-1].directory != directory {
		t.Fatal("a cd segment must carry its directory into the following command")
	}
	commands, err = inspectShell("cd /missing; printf x > /fixture/protected", "/fixture", 0)
	if err != nil || len(commands) == 0 || !contains(commands[len(commands)-1].directories, "/fixture") {
		t.Fatal("a possibly failing cd must retain the original candidate directory")
	}
	commands, err = inspectShell("true; export A=$B > /fixture/protected", "/fixture", 0)
	_, writes, _, _ := compoundEffects(commands)
	if err == nil || !contains(writes, "/fixture/protected") {
		t.Fatal("a failed state segment must retain later literal redirect effects")
	}
	if commands, err := inspectShell("export A=1; git push origin main", "/fixture", 0); err != nil || len(commands) == 0 {
		t.Fatal("an environment state segment must not make later argv opaque")
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

func TestCompoundErrorKinds(t *testing.T) {
	for _, body := range []string{"eval /fixture/unknown", "sh -c '/fixture/unknown'", "tmux new-session '/fixture/unknown'"} {
		commands, err := inspectShell("true; "+body+" > /fixture/body-log; touch /fixture/after", "/fixture", 0)
		_, writes, _, opaque := compoundEffects(commands)
		if err != nil || !opaque || !contains(writes, "/fixture/body-log") || !contains(writes, "/fixture/after") {
			t.Fatalf("a literal nested-body gap must stay opaque and retain every segment's effects: %s: %v", body, err)
		}
	}
	for _, body := range []string{"export A=$B", "cd $D", ". $F", "LANEBOSS_LANE=b1 true", "env LANEBOSS_ROLE=mini-b true",
		"eval /fixture/unknown > $TARGET", "source /dev/stdin <<< literal"} {
		if _, err := inspectShell("true; "+body, "/fixture", 0); err == nil {
			t.Fatalf("an enclosing argv or redirect error must stay fatal: %s", body)
		}
	}
	commands, err := inspectShell("true; cd /fixture > $TARGET > /fixture/protected", "/fixture", 0)
	_, writes, _, _ := compoundEffects(commands)
	if err == nil || !contains(writes, "/fixture/protected") {
		t.Fatal("a nonliteral redirect must not discard the following literal redirect")
	}
}

func TestCompoundChainErrors(t *testing.T) {
	_, first := inspectShell("true; cd \"$DIR\"", "/fixture", 0)
	if first == nil {
		t.Fatal("the failing state segment must keep its inspection error")
	}
	for _, link := range []string{" && ", " || ", " | "} {
		script := "cd \"$DIR\"" + link + "eval 'git push origin main'" + link + "cd \"$NEXT\"" + link + "printf x > /fixture/protected"
		commands, err := inspectShell(script, "/fixture", 0)
		if err == nil || err.Error() != first.Error() {
			t.Fatalf("the chain must return its first link's error: %s: %v", link, err)
		}
		push, write := false, false
		for _, cmd := range commands {
			if reflect.DeepEqual(cmd.argv, []string{"git", "push", "origin", "main"}) {
				push = true
				if !cmd.directoryUncertain {
					t.Fatal("a nested push after a failed link must keep uncertain directory state")
				}
			}
			if contains(cmd.writes, "/fixture/protected") {
				write = true
				if !cmd.directoryUncertain || !contains(cmd.directories, "/fixture") {
					t.Fatal("a later write must keep uncertainty and the original directory candidate")
				}
			}
		}
		if !push || !write {
			t.Fatalf("failed links must not discard later nested commands or redirects: %s", link)
		}
	}
}
