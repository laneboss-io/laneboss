// Package orghook implements the org's data-driven PreToolUse policy and runner checks.
// Commands are inspected, never executed. Diagnostics deliberately exclude input values.
package orghook

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Run executes hook, refusals or check-hooks and returns the process exit code.
func Run(action string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	switch action {
	case "hook":
		runner, pinned := "", ""
		for i := 0; i < len(args); i++ {
			key, value, next, err := cliOption(args, i)
			if err != nil || (key != "--runner" && key != "--instance") {
				fmt.Fprintln(stderr, "laneboss org hook: expected --runner claude|codex [--instance FILE]")
				return 2
			}
			i = next
			if key == "--runner" {
				runner = value
			} else {
				pinned = value
			}
		}
		if runner != "claude" && runner != "codex" {
			fmt.Fprintln(stderr, "laneboss org hook: --runner must be claude or codex")
			return 2
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
				if err != nil || key != "--format" || (value != "text" && value != "json") {
					fmt.Fprintln(stderr, "laneboss org refusals: expected ORG [--format text|json]")
					return 2
				}
				format, i = value, next
			} else if org == "" {
				org = args[i]
			} else {
				fmt.Fprintln(stderr, "laneboss org refusals: expected one org path")
				return 2
			}
		}
		if org == "" {
			fmt.Fprintln(stderr, "laneboss org refusals: ORG is required")
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
			fmt.Fprintln(stderr, "laneboss org check-hooks: expected ORG")
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
		fmt.Fprintln(stderr, "laneboss org: unknown hook action")
		return 2
	}
}

func cliOption(args []string, index int) (string, string, int, error) {
	for i, c := range args[index] {
		if c == '=' {
			return args[index][:i], args[index][i+1:], index, nil
		}
	}
	if index+1 >= len(args) {
		return "", "", index, invalid("a command option needs a value")
	}
	return args[index], args[index+1], index + 1, nil
}

func hookDecision(stdin io.Reader, runner, pinned string) (allowed bool, reason string) {
	defer func() {
		if recover() != nil {
			allowed, reason = false, "org hook fails closed: internal inspection failure"
		}
	}()
	data, err := io.ReadAll(io.LimitReader(stdin, maxBytes+1))
	if err != nil {
		return false, "org hook fails closed: the hook event is unreadable"
	}
	if len(data) > maxBytes {
		return false, "org hook fails closed: the hook event exceeds 2 MiB"
	}
	event, err := parseJSON(data, "the hook event")
	if err != nil {
		return false, "org hook fails closed: " + err.Error()
	}
	allowed, reason, err = decide(event, runner, pinned)
	if err != nil {
		return false, "org hook fails closed: " + err.Error()
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
