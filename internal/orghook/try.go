package orghook

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/decisionsrv"
	"laneboss.io/laneboss/internal/rolepolicy"
)

const tryUsage = "usage: laneboss org blacklist try --config NAME [--level N --role ROLE] -- COMMAND..."

type tryOptions struct {
	config, role string
	level        int
	command      []string
}

func parseTryArgs(args []string) (tryOptions, error) {
	options := tryOptions{level: 3, role: "executor"}
	separator := -1
	for i, value := range args {
		if value == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		return options, invalid(tryUsage)
	}
	for i := 0; i < separator; i++ {
		key, value, inline := strings.Cut(args[i], "=")
		if !inline {
			if i+1 >= separator || strings.HasPrefix(args[i+1], "--") {
				return options, invalid(tryUsage)
			}
			value = args[i+1]
			i++
		}
		switch key {
		case "--config":
			if options.config != "" {
				return options, invalid(tryUsage)
			}
			options.config = value
		case "--level":
			var err error
			if options.level, err = parseTryLevel(value); err != nil {
				return options, err
			}
		case "--role":
			if err := rolepolicy.CheckName(value); err != nil {
				return options, err
			}
			options.role = value
		default:
			return options, invalid(tryUsage)
		}
	}
	if options.config == "" || len(args) == separator+1 {
		return options, invalid(tryUsage)
	}
	options.command = append([]string(nil), args[separator+1:]...)
	return options, nil
}

func parseTryLevel(value string) (int, error) {
	if value == "3" || value == "4" || value == "5" || value == "6" {
		return int(value[0] - '0'), nil
	}
	return 0, invalid("--level must be an integer from 3 to 6")
}

func runBlacklistTry(args []string, stdout, stderr io.Writer) int {
	if lane := os.Getenv("LANEBOSS_LANE"); lane != "" {
		fmt.Fprintln(stderr, "laneboss org blacklist try: a preview cannot run inside a lane session")
		return 2
	}
	options, err := parseTryArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	loaded, err := config.Load(options.config)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	root, err := rolepolicy.ConfigRoot(loaded.Home, loaded.Data)
	if err != nil || root == "" {
		fmt.Fprintln(stderr, "the configuration has no org folder")
		return 2
	}
	home := filepath.Join(root, ".laneboss")
	policy, err := parseHookBlacklist(home)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	inst := &instance{home: home, directory: home, name: options.role, role: options.role, level: options.level, hookMode: policy.mode, blacklist: policy.blacklist}
	inst.blacklist, inst.blacklistSources, err = effectiveHookBlacklist(home, options.level, options.role, inst.blacklist)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	cwd := root
	commandText := strings.Join(options.command, " ")
	runner := "claude"
	event := map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": "Bash", "tool_input": map[string]any{"command": commandText}}
	if strings.HasPrefix(strings.TrimSpace(commandText), "{") {
		if parsed, parseErr := parseJSON([]byte(commandText), "sample tool call"); parseErr == nil {
			event = parsed
			if event["hook_event_name"] == nil {
				event["hook_event_name"] = "PreToolUse"
			}
			if event["cwd"] == nil {
				event["cwd"] = cwd
			}
			if tool, ok := event["tool_name"].(string); ok && strings.HasPrefix(tool, "functions.") {
				runner = "codex"
			}
		}
	}
	act, err := eventAction(event, runner, cwd)
	if err != nil {
		if !isObservationGap(err) {
			fmt.Fprintln(stderr, err.Error())
			return 2
		}
		if act.tool == "" {
			act.tool = "Bash"
		}
		rawDirectory := cwd
		if act.rawDirectory != "" {
			rawDirectory = act.rawDirectory
		}
		if len(act.commands) == 0 {
			act.commands = []command{{argv: []string{act.tool}, directory: rawDirectory, opaque: true}}
		}
		for i := range act.commands {
			act.commands[i].opaque = true
		}
	}
	writes, reads, metadata, _, err := actionEffects(act, cwd)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	rawDirectory := cwd
	if act.rawDirectory != "" {
		rawDirectory = act.rawDirectory
	}
	if reason, policyErr := builtInWriteRefusal(inst, writes); policyErr != nil {
		fmt.Fprintln(stderr, policyErr.Error())
		return 2
	} else if reason != "" {
		result := map[string]any{"config": options.config, "level": options.level, "role": options.role, "command": commandText, "judge": "unavailable", "entries": []any{map[string]any{"id": "laneboss-files", "description": "Laneboss protected paths", "band": "refuse", "pattern_matched": true, "score": nil, "judge_band": "unavailable", "decision": "refuse"}}, "decision": "refuse"}
		return writeTryResult(stdout, result)
	}
	needsRaw := act.gap
	for _, command := range act.commands {
		needsRaw = needsRaw || command.opaque || command.changesState || command.directoryUncertain
	}
	if needsRaw {
		if reason, rawErr := builtInRawWriteRefusal(inst, act.raw, rawDirectory, act.rawEnvironment, act.rawDirectories...); rawErr != nil {
			fmt.Fprintln(stderr, rawErr.Error())
			return 2
		} else if reason != "" {
			result := map[string]any{"config": options.config, "level": options.level, "role": options.role, "command": commandText, "judge": "unavailable", "entries": []any{map[string]any{"id": "laneboss-files", "description": "Laneboss protected paths", "band": "refuse", "pattern_matched": true, "score": nil, "judge_band": "unavailable", "decision": "refuse"}}, "decision": "refuse"}
			return writeTryResult(stdout, result)
		}
	}
	allRows, err := blacklistGuardRows(inst)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	rows := []blacklistRule{}
	for _, row := range allRows {
		if blacklistScopeApplies(row, inst) && (blacklistHasDeterministic(row) || (row.decision == "" && row.job == "")) {
			rows = append(rows, row)
		}
	}
	result := map[string]any{"config": options.config, "level": options.level, "role": options.role, "command": commandText, "judge": "unavailable", "entries": []any{}, "decision": "allow"}
	if len(rows) == 0 {
		return writeTryResult(stdout, result)
	}
	judged := map[string]decisionsrv.Scored{}
	judgeName := ""
	judgeRows := []blacklistRule{}
	for _, row := range inst.blacklist {
		if !row.patternOnly && blacklistScopeApplies(row, inst) {
			judgeRows = append(judgeRows, row)
		}
	}
	guide, guideErr := decisionsrv.OpenGuide(home)
	if len(judgeRows) > 0 && guideErr == nil && guide.Present && guide.SettingsErr == nil && guide.Settings.Enabled && guide.HasStore() && guide.Settings.Judge != "" {
		judgeName = guide.Settings.Judge
		candidates := make([]decisionsrv.BlacklistCandidate, len(judgeRows))
		for i, row := range judgeRows {
			candidates[i] = decisionsrv.BlacklistCandidate{ID: row.id, Description: row.description, ExamplesNotOK: row.examplesNotOK, ExamplesOK: row.examplesOK}
		}
		scored := guide.JudgeBlacklistWithin(candidates, guardActionText(event, runner, act), 2*time.Second)
		for _, item := range scored {
			judged[item.Decision.ID] = item
		}
	}
	result["judge"] = judgeName
	entries := []any{}
	decision := "allow"
	for _, row := range rows {
		patternMatched, matchErr := blacklistMatches(row, inst, act, writes, reads, metadata, act.searches, cwd)
		if matchErr != nil {
			fmt.Fprintln(stderr, matchErr.Error())
			return 2
		}
		entry := map[string]any{"id": row.id, "description": row.description, "band": row.band, "pattern_matched": patternMatched, "score": nil, "judge_band": "unavailable", "decision": "allow"}
		if row.patternOnly {
			entry["judge_band"] = "not-applicable"
		}
		if item, ok := judged[row.id]; ok && item.Answered() {
			entry["score"] = item.Score
			entry["judge_band"] = item.Band.String()
		}
		outcome := "allow"
		if patternMatched {
			if row.band == "refuse" {
				outcome = "refuse"
			} else {
				outcome = "warn"
			}
		} else if item, ok := judged[row.id]; ok && item.Answered() {
			if row.band == "refuse" && item.Score >= guide.Settings.RefuseAt {
				outcome = "refuse"
			} else if item.Score >= guide.Settings.WarnAt {
				outcome = "warn"
			}
		}
		entry["decision"] = outcome
		entries = append(entries, entry)
		if outcome == "refuse" {
			decision = "refuse"
		} else if outcome == "warn" && decision == "allow" {
			decision = "warn"
		}
	}
	result["entries"] = entries
	result["decision"] = decision
	return writeTryResult(stdout, result)
}

func writeTryResult(stdout io.Writer, result map[string]any) int {
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return 1
	}
	return 0
}
