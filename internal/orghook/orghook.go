// Package orghook implements the org's data-driven PreToolUse policy and runner checks.
// Commands are inspected, never executed. Diagnostics deliberately exclude input values.
package orghook

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"laneboss.io/laneboss/internal/cliargs"
	"laneboss.io/laneboss/internal/hookconfig"
)

// Run executes hook, refusals or check-hooks and returns the process exit code.
func Run(action string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	switch action {
	case "vet-codex":
		home, worktree := "", ""
		for i := 0; i < len(args); i++ {
			key, value, next, err := cliOption(args, i)
			if err != nil || (key != "--home" && key != "--worktree") {
				fmt.Fprintln(stderr, "laneboss org vet-codex: requires --home and --worktree")
				return 2
			}
			if key == "--home" {
				home = value
			} else {
				worktree = value
			}
			i = next
		}
		if home == "" || worktree == "" {
			fmt.Fprintln(stderr, "laneboss org vet-codex: requires --home and --worktree")
			return 2
		}
		if err := hookconfig.VetCodexEnvironment(os.Environ()); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		if err := hookconfig.VetCodex(home, worktree); err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 2
		}
		return 0
	case "hook":
		runner, pinned := "", ""
		for i := 0; i < len(args); i++ {
			key, value, next, err := cliOption(args, i)
			if err != nil {
				return cliargs.Print(stderr, "laneboss org hook", "usage: laneboss org hook --runner {claude,codex} [--instance FILE]", err.Error())
			}
			if key != "--runner" && key != "--instance" {
				return cliargs.Print(stderr, "laneboss org hook", "usage: laneboss org hook --runner {claude,codex} [--instance FILE]", cliargs.Reject(""))
			}
			i = next
			if key == "--runner" {
				runner = value
			} else {
				pinned = value
			}
		}
		if runner == "" {
			return cliargs.Print(stderr, "laneboss org hook", "usage: laneboss org hook --runner {claude,codex} [--instance FILE]", cliargs.Required("--runner"))
		}
		if runner != "claude" && runner != "codex" {
			return cliargs.Print(stderr, "laneboss org hook", "usage: laneboss org hook --runner {claude,codex} [--instance FILE]", cliargs.Reject("--runner"))
		}
		allowed, reason := hookDecision(stdin, runner, pinned)
		decision := "deny"
		if allowed {
			decision = "allow"
		}
		if json.NewEncoder(stdout).Encode(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason,
		}}) != nil {
			return 1
		}
		return 0
	case "refusals":
		org, format := "", "text"
		for i := 0; i < len(args); i++ {
			if len(args[i]) > 0 && args[i][0] == '-' {
				key, value, next, err := cliOption(args, i)
				if err != nil {
					return cliargs.Print(stderr, "laneboss org refusals", "usage: laneboss org refusals ORG [--format {text,json}]", err.Error())
				}
				if key != "--format" {
					return cliargs.Print(stderr, "laneboss org refusals", "usage: laneboss org refusals ORG [--format {text,json}]", cliargs.Reject(""))
				}
				if value != "text" && value != "json" {
					return cliargs.Print(stderr, "laneboss org refusals", "usage: laneboss org refusals ORG [--format {text,json}]", cliargs.Reject("--format"))
				}
				format, i = value, next
			} else if org == "" {
				org = args[i]
			} else {
				fmt.Fprintln(stderr, "laneboss org refusals: error: "+cliargs.Reject(""))
				return 2
			}
		}
		if org == "" {
			fmt.Fprintln(stderr, "laneboss org refusals: error: "+cliargs.Required("ORG"))
			return 2
		}
		records, err := listRefusals(org)
		if err != nil {
			fmt.Fprintln(stderr, "laneboss org refusals: "+err.Error())
			return 1
		}
		if format == "json" {
			if json.NewEncoder(stdout).Encode(records) != nil {
				return 1
			}
		} else {
			for _, record := range records {
				if _, err := fmt.Fprintf(stdout, "%s\n%s\n\n", record["source"], refusalText(record, "")); err != nil {
					return 1
				}
			}
		}
		return 0
	case "check-hooks":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "laneboss org check-hooks: error: "+cliargs.Reject(""))
			return 2
		}
		report, err := CheckHooks(args[0])
		if err != nil {
			report = map[string]any{"ok": false, "checks": []any{map[string]any{"ok": false, "reason": err.Error()}}}
		}
		if json.NewEncoder(stdout).Encode(report) != nil {
			return 1
		}
		if report["ok"] == true {
			return 0
		}
		return 1
	default:
		fmt.Fprintln(stderr, "laneboss org: error: "+cliargs.Reject("ACTION"))
		return 2
	}
}

func cliOption(args []string, index int) (string, string, int, error) {
	key, value, inline := strings.Cut(args[index], "=")
	if key != "--runner" && key != "--instance" && key != "--format" && key != "--home" && key != "--worktree" {
		return "", "", index, invalid(cliargs.Reject(""))
	}
	if inline {
		return key, value, index, nil
	}
	if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
		return "", "", index, invalid(cliargs.Expected(key))
	}
	return key, args[index+1], index + 1, nil
}
func hookDecision(stdin io.Reader, runner, pinned string) (allowed bool, reason string) {
	defer func() {
		if recover() != nil {
			allowed, reason = false, errorRefusal("internal inspection failure")
		}
	}()
	data, err := io.ReadAll(io.LimitReader(stdin, maxBytes+1))
	if err != nil {
		return false, errorRefusal("the hook event is unreadable")
	}
	if len(data) > maxBytes {
		return false, errorRefusal("the hook event exceeds 2 MiB")
	}
	event, err := parseJSON(data, "the hook event")
	if err != nil {
		return false, errorRefusal(err.Error())
	}
	allowed, reason, err = decide(event, runner, pinned)
	if err != nil {
		allowed, reason = false, eventErrorRefusal(err.Error(), event)
	}
	if err := recordCallback(event, runner, pinned, allowed, reason); err != nil {
		return false, errorRefusal("callback receipt could not be kept")
	}
	return allowed, reason
}

func currentDirectory() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", invalid("the working directory cannot be resolved")
	}
	return directory, nil
}
