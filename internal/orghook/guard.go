package orghook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/decisionsrv"
	"laneboss.io/laneboss/internal/faults"
)

// The decision guard (docs/decisions.md, "Guiding agents"). After the org policy has allowed a tool call, the guard
// asks the org's judge, once for each recorded decision that bears on the call, whether the call conflicts with it.
// The warning threshold puts an applicable decision in front of the agent as
// additional context; below the warning threshold nothing changes. A call it
// cannot score is never allowed silently: it receives a warning that says so.
//
// The guard only ever adds to the org policy's answer. It is called with a call the policy has already allowed, and what
// it returns is a plain allow (the policy's own words) or an allow with a
// warning: no result of the guard can allow a call that the policy refused. A
// missing guide adds nothing and unusable settings warn by default. Read-only
// tools stay exempt. A call that was not read whole, a text that the judge was
// not given, a decision that max_decisions left out and a judge that gave no
// answer are all reported, and a clean allow means that every decision that
// applies was judged on the whole call.

const (
	guardTag            = "[decision-guard]"
	guardSettingsPath   = ".laneboss/shared/services/guide.toml"
	guardRefuseLimit    = 3 // refusing decisions quoted in one refusal
	guardRefuseAnswer   = 800
	guardRefuseAsked    = 300
	guardWarnAnswer     = 400
	guardWarnAsked      = 200
	guardUnscoredAns    = 300
	guardUnscoredAsked  = 150
	guardNoticeListed   = 3 // decisions that a notice or a warning about unscored decisions names
	guardNoticeAnswer   = 200
	guardNoticeAsked    = 100
	guardNoteLimit      = 40 // decisions that a callback receipt lists
	blacklistJudgeLimit = 2 * time.Second
)

var guardShellTools = []string{"Bash", "exec_command", "shell", "shell_command"}

// guardQuestionTools are the tools whose call is a question to the owner. The org policy allows only request_user_input
// among them; any other question tool is an unknown tool, which the policy refuses.
var guardQuestionTools = []string{"request_user_input"}
var guardWriteTools = []string{"Write", "Edit", "MultiEdit", "NotebookEdit", "write_file", "edit_file"}

// guardExempt is true for the tools that only read the local file system: a read cannot change anything, so it is not
// judged. Every other allowed call is.
func guardExempt(act action) bool {
	return contains([]string{"Read", "read_file", "Glob", "LS", "Grep"}, act.tool)
}

// guardWriteSkipped are the fields of a file-writing tool that are not sent to the judge as JSON: the path is in the
// first line, the text that is written follows as it is, and a text that is replaced or a flag is not what the call does.
var guardWriteSkipped = map[string]bool{"file_path": true, "notebook_path": true, "path": true, "content": true,
	"new_string": true, "new_source": true, "old_string": true, "replace_all": true, "edits": true}

// guardActionText renders the whole call for the judge: the tool and its command or target, and for a write everything
// that it writes. It never cuts the call: the judge asks are made in windows over all of it (decisionsrv.ActionWindows),
// and a call that is longer than the windows is reported as not read. A text that looks like a credential is withheld by
// the judge machinery before anything is sent, and the guard then reports the call as not scored.
func guardActionText(event map[string]any, runner string, act action) string {
	input := event["tool_input"]
	if text, ok := input.(string); ok && runner == "codex" {
		if act.tool == "apply_patch" {
			return "apply_patch\n" + text
		}
		if parsed, err := parseJSON([]byte(text), "tool_input"); err == nil {
			input = parsed
		}
	}
	data, _ := object(input)
	text := ""
	switch {
	case contains(guardShellTools, act.tool):
		for _, key := range []string{"command", "cmd", "argv"} {
			switch value := data[key].(type) {
			case string:
				text = value
			case []any:
				words := []string{}
				for _, word := range value {
					if s, ok := word.(string); ok {
						words = append(words, s)
					}
				}
				text = strings.Join(words, " ")
			}
			if text != "" {
				break
			}
		}
		text = act.tool + ": " + text
	case contains(guardWriteTools, act.tool):
		path := ""
		for _, key := range []string{"file_path", "notebook_path", "path"} {
			if s, ok := data[key].(string); ok {
				path = s
			}
		}
		text = act.tool + " " + path
		if act.tool == "MultiEdit" && faults.Get("guide-multiedit-path-only").Point != "" {
			// The mutant: only the path of a multiple edit is judged, as if what it writes were not part of the call.
			_ = faults.Reach("guide-multiedit-path-only")
			return text
		}
		for _, key := range []string{"content", "new_string", "new_source"} {
			if s, ok := data[key].(string); ok {
				text += "\n" + s
			}
		}
		// A multiple edit carries what it writes in an array of edits, and any other field of the call goes in as JSON:
		// nothing that the call carries stays out of what the judge reads.
		if edits, ok := data["edits"].([]any); ok {
			for _, edit := range edits {
				if item, ok := edit.(map[string]any); ok {
					for _, key := range []string{"content", "new_string", "new_source"} {
						if s, ok := item[key].(string); ok {
							text += "\n" + s
						}
					}
				}
			}
		}
		rest := map[string]any{}
		for key, value := range data {
			if !guardWriteSkipped[key] {
				rest[key] = value
			}
		}
		if len(rest) > 0 {
			if encoded, err := json.Marshal(rest); err == nil {
				text += "\n" + string(encoded)
			}
		}
	case act.tool == "apply_patch":
		for _, key := range []string{"input", "patch", "command"} {
			if s, ok := data[key].(string); ok {
				text = "apply_patch\n" + s
				break
			}
		}
	default:
		encoded, err := json.Marshal(data)
		if err == nil {
			text = act.tool + ": " + string(encoded)
		} else {
			text = act.tool
		}
	}
	return text
}

// guardCall runs after the org policy has allowed a call (allowedReason is the policy's own words). It returns whether
// the call is allowed, the reason to give, the additional context to put in front of the agent (empty unless the call
// is allowed with a warning) and a summary for the callback receipt (nil when the guard asked nobody anything).
func guardCall(inst *instance, act action, event map[string]any, runner, allowedReason string, parents ...context.Context) (bool, string, string, map[string]any) {
	if (strings.Contains(allowedReason, "] Refuses:") || strings.HasPrefix(allowedReason, "[blacklist:laneboss-files]")) && faults.Get("guide-guard-overrides-refusal").Point == "" {
		return false, allowedReason, "", nil
	}
	{
		allowed, reason, context, note := blacklistGuardCall(inst, act, event, runner, allowedReason)
		if !allowed {
			return allowed, reason, context, note
		}
		guideAllowed, guideReason, guideContext, guideNote := guardDecisionCall(inst, act, event, runner, reason, parents...)
		if !guideAllowed {
			return guideAllowed, guideReason, joinGuardContext(context, guideContext), mergeGuardNotes(note, guideNote)
		}
		return true, guideReason, joinGuardContext(context, guideContext), mergeGuardNotes(note, guideNote)
	}
}

func joinGuardContext(first, second string) string {
	if first == "" {
		return second
	}
	if second == "" {
		return first
	}
	return first + "\n\n" + second
}

func mergeGuardNotes(first, second map[string]any) map[string]any {
	if first == nil {
		return second
	}
	if second == nil {
		return first
	}
	merged := map[string]any{}
	for key, value := range second {
		merged[key] = value
	}
	merged["blacklist"] = first
	for key, value := range first {
		merged["blacklist_"+key] = value
	}
	return merged
}

func blacklistGuardRows(inst *instance) ([]blacklistRule, error) {
	rules, err := loadRules(inst)
	if err != nil {
		return nil, err
	}
	legacy, err := legacyBlacklistRows(rules, inst)
	if err != nil {
		return nil, err
	}
	return append(legacy, inst.blacklist...), nil
}

func blacklistNotice(reason string, rows []blacklistRule, judge string) (bool, string, string, map[string]any) {
	ids := make([]any, 0, len(rows))
	for i, row := range rows {
		if i == guardNoticeListed {
			break
		}
		ids = append(ids, row.id)
	}
	context := fmt.Sprintf("[blacklist-judge] This tool call was NOT checked against %d applicable blacklist entr%s: %s. Continue only when the call is permitted by the org's descriptions.", len(rows), map[bool]string{true: "y", false: "ies"}[len(rows) == 1], reason)
	if len(ids) > 0 {
		context += " Entries: " + strings.Trim(strings.Join(stringValues(ids), ", "), " ") + "."
	}
	return true, "org policy permits this tool call; the blacklist judge has a warning for the agent", context,
		map[string]any{"band": "unavailable", "judge": judge, "reason": reason, "entries": ids}
}

func stringValues(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func blacklistHasDeterministic(row blacklistRule) bool {
	return len(row.argv) > 0 || len(row.argvWords) > 0 || row.pathGlob != "" || row.toolGlob != "" || len(row.pathRoots) > 0 || row.legacySecret
}

func blacklistJudgeUnavailableReason(act action, reason string) string {
	for _, command := range act.commands {
		if command.opaque {
			return reason + "; the call was opaque, so no deterministic file effects were available"
		}
	}
	return reason
}

func blacklistGuardCall(inst *instance, act action, event map[string]any, runner, allowedReason string) (bool, string, string, map[string]any) {
	_, err := blacklistGuardRows(inst)
	if err != nil {
		return true, allowedReason, "[blacklist-judge] This tool call was NOT checked because the blacklist entries could not be loaded; report the configuration problem to the supervisor before relying on the call.", map[string]any{"band": "unavailable", "reason": "entries"}
	}
	applicable := []blacklistRule{}
	// Legacy generated rows retain their deterministic refusal behavior, but
	// they are compatibility data rather than TypeSafe descriptions. Judge only
	// authored org entries so one ordinary call does not fan out into a request
	// per protected path.
	for _, row := range inst.blacklist {
		if !row.patternOnly && blacklistScopeApplies(row, inst) && (blacklistHasDeterministic(row) || (row.decision == "" && row.job == "")) {
			applicable = append(applicable, row)
		}
	}
	if len(applicable) == 0 {
		return true, allowedReason, "", nil
	}
	g, err := decisionsrv.OpenGuide(inst.home)
	if err != nil {
		return blacklistUnavailableNotice(allowedReason, applicable, blacklistJudgeUnavailableReason(act, "the org decision settings or store could not be opened"), "")
	}
	if !g.Present {
		// A missing guide has never enabled a judge. Deterministic legacy and
		// argv/path rows have already been decided by the hook, so they do not
		// need a second "not checked" banner; only description-only entries
		// remain unscored and deserve the notice.
		unscored := make([]blacklistRule, 0, len(applicable))
		for _, row := range applicable {
			if !blacklistHasDeterministic(row) {
				unscored = append(unscored, row)
			}
		}
		if len(unscored) == 0 {
			return true, allowedReason, "", nil
		}
		return blacklistUnavailableNotice(allowedReason, unscored, "the org has no usable TypeSafe decision guide", "")
	}
	if g.SettingsErr != nil || !g.Settings.Enabled || !g.HasStore() {
		return blacklistUnavailableNotice(allowedReason, applicable, blacklistJudgeUnavailableReason(act, "the org has no usable TypeSafe decision guide"), "")
	}
	if g.Settings.Judge == "" {
		return blacklistUnavailableNotice(allowedReason, applicable, blacklistJudgeUnavailableReason(act, "guide.toml names no TypeSafe judge"), "")
	}
	candidates := make([]decisionsrv.BlacklistCandidate, len(applicable))
	for i, row := range applicable {
		candidates[i] = decisionsrv.BlacklistCandidate{ID: row.id, Description: row.description, ExamplesNotOK: row.examplesNotOK, ExamplesOK: row.examplesOK}
	}
	scored := g.JudgeBlacklistWithin(candidates, guardActionText(event, runner, act), blacklistJudgeLimit)
	warnings := []decisionsrv.Scored{}
	missing := false
	noteRows := []any{}
	for i, item := range scored {
		row := applicable[i]
		entry := map[string]any{"entry": row.id, "outcome": item.Outcome, "score": nil, "band": item.Band.String()}
		if item.Answered() {
			entry["score"] = item.Score
		}
		noteRows = append(noteRows, entry)
		if !item.Answered() {
			missing = true
			continue
		}
		if row.band == "refuse" && item.Score >= g.Settings.RefuseAt {
			return false, blacklistText(row, false, fmt.Sprintf("TypeSafe judge scored %.2f at or above refuse_threshold %.2f", item.Score, g.Settings.RefuseAt)), "", map[string]any{"band": "refuse", "judge": g.Settings.Judge, "entries": noteRows}
		}
		if item.Score >= g.Settings.WarnAt {
			warnings = append(warnings, item)
		}
	}
	if missing {
		allowed, reason, context, note := blacklistUnavailableNotice(allowedReason, applicable, blacklistJudgeUnavailableReason(act, "TypeSafe did not return a score before the hook deadline"), g.Settings.Judge)
		if len(warnings) > 0 {
			context = joinGuardContext(context, blacklistScoredWarning(warnings))
		}
		note["entries"] = noteRows
		return allowed, reason, context, note
	}
	note := map[string]any{"band": "none", "judge": g.Settings.Judge, "entries": noteRows}
	if len(warnings) > 0 {
		note["band"] = "warn"
		var b strings.Builder
		fmt.Fprintf(&b, "[blacklist-judge] TypeSafe found %d applicable blacklist entr%s that may bear on this tool call. The call is allowed; check the descriptions before continuing.\n", len(warnings), map[bool]string{true: "y", false: "ies"}[len(warnings) == 1])
		for _, item := range warnings {
			fmt.Fprintf(&b, "- [%s] %s [score %.2f]\n", item.Decision.ID, item.Decision.Answer, item.Score)
		}
		return true, allowedReason + "; the blacklist judge has a warning for the agent", strings.TrimRight(b.String(), "\n"), note
	}
	return true, allowedReason, "", note
}

func blacklistUnavailableNotice(allowedReason string, rows []blacklistRule, reason, judge string) (bool, string, string, map[string]any) {
	_, _, context, note := blacklistNotice(reason, rows, judge)
	return true, allowedReason + "; the blacklist judge has a warning for the agent", context, note
}

func blacklistScoredWarning(items []decisionsrv.Scored) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[blacklist-judge] %d entry score(s) were available before another entry became unscored; those warnings still apply:\n", len(items))
	for _, item := range items {
		fmt.Fprintf(&b, "- [%s] %s [score %.2f]\n", item.Decision.ID, item.Decision.Answer, item.Score)
	}
	return strings.TrimRight(b.String(), "\n")
}

func guardDecisionCall(inst *instance, act action, event map[string]any, runner, allowedReason string, parents ...context.Context) (bool, string, string, map[string]any) {
	if guardExempt(act) && !settingsRefuseAll(false) {
		return true, allowedReason, "", nil
	}
	g, err := decisionsrv.OpenGuide(inst.home)
	if err != nil {
		return guardStoreUnlocatable(inst, allowedReason)
	}
	switch {
	case !g.Present:
		return true, allowedReason, "", nil // the org never set the guard up: no decision applies
	case g.SettingsErr != nil:
		return guardInvalidSettings(g.Settings, g.SettingsErr, allowedReason)
	case !g.Settings.Enabled:
		return true, allowedReason, "", nil
	case !g.HasStore():
		return true, allowedReason, "", map[string]any{"band": "unavailable", "reason": "no-store"}
	}
	decisions, err := g.HookDecisions(inst.level, inst.name)
	if err != nil {
		return true, allowedReason + "; the decision guard has a warning for the agent", guardTag + " This tool call was NOT checked against the recorded decisions: the decision store could not be read. Ask the supervisor which decisions apply before you go on.", map[string]any{"band": "unavailable", "reason": "store"}
	}
	if len(decisions) == 0 {
		return true, allowedReason, "", nil
	}
	if g.Settings.Judge == "" {
		// With no judge there is no score to act on, and the guard cannot refuse: it tells the agent which decisions
		// apply, and that this call was not checked against them. The same decisions are in the agent's brief.
		return guardNotice(decisions, allowedReason)
	}
	text := guardActionText(event, runner, act)
	asked, left := decisionsrv.SelectDecisions(decisions, text, g.Settings.MaxDecisions)
	var scored []decisionsrv.Scored
	question := contains(guardQuestionTools, act.tool)
	if question {
		// The call is a question to the owner: the judge is asked whether a decision already answers it.
		scored = g.JudgeAnswers(asked, text, parents...)
	} else {
		scored = g.JudgeConflicts(asked, text, parents...)
	}
	// What max_decisions left out was not judged. The ranking that picks the decisions to ask about reads the agent's own
	// text, so a decision that it leaves out is reported like one that the judge could not score.
	scored = append(scored, decisionsrv.NotAsked(left)...)
	allowed, reason, context, note := guardVerdict(g.Settings, scored, allowedReason, question)
	if g.Capped {
		note["scope_capped"] = true
		if allowed {
			context = strings.TrimSpace(context + "\n" + guardTag + " More than 1,000 records apply to this scope; the remaining records were not checked.")
		}
	}
	return allowed, reason, context, note
}

// guardStoreUnlocatable is the guard's answer when the org's history settings cannot be read, so that the decision store
// cannot be found. A missing or disabled guide adds nothing. Unusable settings follow their failure policy.
// Otherwise the call is allowed with a warning that it was not checked.
func guardStoreUnlocatable(inst *instance, allowedReason string) (bool, string, string, map[string]any) {
	settings, present, err := decisionsrv.ReadGuideSettings(inst.home)
	note := map[string]any{"band": "unavailable", "reason": "history-settings"}
	if err != nil {
		return guardInvalidSettings(settings, err, allowedReason)
	}
	if !present || !settings.Enabled {
		return true, allowedReason, "", nil
	}
	reason := "the org's history settings cannot be read, so the decision store cannot be found"
	return true, allowedReason + "; the decision guard has a warning for the agent", guardTag + " This tool call was NOT checked against the recorded decisions: " + reason + ". Ask the supervisor which decisions apply before you go on.", note
}

func guardInvalidSettings(settings decisionsrv.GuideSettings, err error, allowedReason string) (bool, string, string, map[string]any) {
	field := guardSettingsPath
	var settingsError *decisionsrv.GuideSettingsError
	if errors.As(err, &settingsError) && settingsError.Field != "" {
		field += "." + settingsError.Field
	}
	note := map[string]any{"band": "settings-error", "field": field, "error": err.Error(), "unavailable": settings.OnUnavailable}
	if settingsRefuseAll(true) {
		return false, errorRefusal("config invalid: " + field), "", note
	}
	return true, allowedReason, guardTag + " Warning: config invalid: " + field + "; this tool call was NOT checked against the recorded decisions. Ask the supervisor to repair that field before relying on decision guidance.", note
}

// guardNotice is the warn-only answer when guide.toml names no judge: a short list of the decisions that apply, newest
// first, and the plain words that this call was not checked against them. The call is allowed as the org's rules allowed it.
func guardNotice(decisions []decisionsrv.GuideDecision, allowedReason string) (bool, string, string, map[string]any) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s Recorded decisions apply to this instance, and %s names no judge, so this tool call was NOT checked against them. Check it against them yourself before you go on.\n", guardTag, guardSettingsPath)
	ids := []any{}
	for i, d := range decisions {
		if i < guardNoteLimit {
			ids = append(ids, d.ID)
		}
		if i < guardNoticeListed {
			fmt.Fprintf(&b, "- %s\n", d.Describe(guardNoticeAnswer, guardNoticeAsked))
		}
	}
	if more := len(decisions) - guardNoticeListed; more > 0 {
		fmt.Fprintf(&b, "(%d more decisions apply and are not listed here: they are in your brief.)\n", more)
	}
	note := map[string]any{"band": "notice", "judge": "", "asked": 0, "decisions": ids, "applicable": len(decisions)}
	return true, allowedReason + "; the decision guard has a notice for the agent", strings.TrimRight(b.String(), "\n"), note
}

func guardVerdict(s decisionsrv.GuideSettings, scored []decisionsrv.Scored, allowedReason string, question bool) (bool, string, string, map[string]any) {
	// Ordinary guidance has no refusal authority. Only org blacklist policy
	// may deny a call; a high probability or legacy setting adds advice.
	for i := range scored {
		if scored[i].Answered() && scored[i].Band == decisionsrv.BandRefuse {
			scored[i].Band = decisionsrv.BandWarn
		}
	}
	var warning, missing []decisionsrv.Scored
	for _, item := range scored {
		switch {
		case !item.Answered():
			missing = append(missing, item)
		case item.Band == decisionsrv.BandWarn:
			warning = append(warning, item)
		}
	}
	byScore := func(items []decisionsrv.Scored) {
		sort.SliceStable(items, func(i, j int) bool { return items[i].Score > items[j].Score })
	}
	byScore(warning)
	note := guardNote(s, scored, warning, missing)
	note["judgment"] = "conflict"
	if question {
		note["judgment"] = "already-answered"
	}
	switch {
	case len(warning) > 0 || len(missing) > 0:
		return true, allowedReason, guardWarning(s, warning, missing), note
	}
	return true, allowedReason, "", note
}

func guardNote(s decisionsrv.GuideSettings, scored, warning, missing []decisionsrv.Scored) map[string]any {
	band := "none"
	switch {
	case len(warning) > 0:
		band = "warn"
	case len(missing) > 0:
		band = "unscored"
	}
	items := []any{}
	asked := 0
	for i, item := range scored {
		if item.Outcome != "not-asked" {
			asked++
		}
		if i >= guardNoteLimit {
			continue
		}
		entry := map[string]any{"decision": item.Decision.ID, "outcome": item.Outcome, "band": item.Band.String(), "score": nil}
		if item.Answered() {
			entry["score"] = item.Score
		}
		items = append(items, entry)
	}
	note := map[string]any{"band": band, "judge": s.Judge, "asked": asked, "decisions": items}
	if omitted := len(scored) - len(items); omitted > 0 {
		note["omitted"] = omitted
	}
	return note
}

// guardUnscoredReason says in words why decisions have no score of the call, one reason for each kind of outcome.
func guardUnscoredReason(s decisionsrv.GuideSettings, missing []decisionsrv.Scored) string {
	seen := map[string]bool{}
	silent, reasons := []string{}, []string{}
	for _, item := range missing {
		if seen[item.Outcome] {
			continue
		}
		seen[item.Outcome] = true
		switch item.Outcome {
		case "not-asked":
			reasons = append(reasons, fmt.Sprintf("the judge is asked about at most max_decisions = %d decisions for one call, and the others were left out", s.MaxDecisions))
		case "withheld":
			reasons = append(reasons, "a text of the ask looks like a credential, so the judge was not given it")
		case "cut":
			reasons = append(reasons, "a text of the ask was cut before it reached the judge")
		case "partial":
			reasons = append(reasons, fmt.Sprintf("the call is longer than the %d characters that the guard reads", decisionsrv.ReadLimit()))
		default:
			silent = append(silent, item.Outcome)
		}
	}
	if len(silent) > 0 {
		sort.Strings(silent)
		reasons = append(reasons, fmt.Sprintf("judge %s gave no answer (%s)", s.Judge, strings.Join(silent, ", ")))
	}
	sort.Strings(reasons)
	return strings.Join(reasons, "; ")
}

// guardListUnscored names the decisions that have no score: the first few with their text, then the ids of the rest, so
// that the agent can look up any of them.
func guardListUnscored(b *strings.Builder, missing []decisionsrv.Scored, listed int) {
	for i, item := range missing {
		if i == listed {
			ids := []string{}
			for _, rest := range missing[i:] {
				if len(ids) == 12 {
					break
				}
				ids = append(ids, rest.Decision.ID)
			}
			more := ""
			if left := len(missing) - i - len(ids); left > 0 {
				more = fmt.Sprintf(" and %d more", left)
			}
			fmt.Fprintf(b, "(%d more decisions were not scored: %s%s)\n", len(missing)-i, strings.Join(ids, ", "), more)
			return
		}
		fmt.Fprintf(b, "- %s\n", item.Decision.Describe(guardUnscoredAns, guardUnscoredAsked))
	}
}

func guardWarning(s decisionsrv.GuideSettings, warning, missing []decisionsrv.Scored) string {
	var b strings.Builder
	if len(warning) > 0 {
		fmt.Fprintf(&b, "%s Recorded decisions that may bear on this tool call (judge %s returned a yes probability at or above the warn threshold %.2f). Near 0.5 means uncertainty, not medium conflict. The call is allowed. Check it against them before you go on.\n", guardTag, s.Judge, s.WarnAt)
		for _, item := range warning {
			fmt.Fprintf(&b, "- %s [yes probability %.2f]\n", item.Decision.Describe(guardWarnAnswer, guardWarnAsked), item.Score)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(&b, "%s This tool call was NOT scored against %d recorded decision(s): %s. They still apply:\n", guardTag, len(missing), guardUnscoredReason(s, missing))
		guardListUnscored(&b, missing, guardNoticeListed)
	}
	return strings.TrimRight(b.String(), "\n")
}
