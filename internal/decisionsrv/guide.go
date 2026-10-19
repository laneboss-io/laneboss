package decisionsrv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/faults"
)

// Guiding agents with the recorded decisions (docs/decisions.md, "Guiding agents"). The decisions that apply to a
// lane's project and level go into its brief and into every turn message; the org hook asks a judge whether a tool
// call conflicts with one and adds probability-based advice; a question that is already decided is
// answered from the record.

// guideKinds are the kinds of record that guide an agent. A ledger, report, board or bulletin entry is history and a
// question_from_owner is a question: none of them is a decision.
var guideKinds = []string{"decision", "answer", "instruction", "preference", "correction", "owner-decision"}

const (
	guideSettingsFile  = "shared/services/guide.toml"
	guideHeading       = "## Recorded decisions that apply to this lane"
	guideBriefMax      = 12   // decisions that a brief or a turn message shows
	guideAnswerBytes   = 600  // bytes of an answer that a brief shows
	guideQuestionBytes = 240  // bytes of a question that a brief shows
	guideStoreRows     = 1000 // most in-force records read for one lookup
	guideWithheld      = "[withheld: looks like a credential]"
)

var guideKeys = wordsSet("enabled jobs configuration judge refuse_threshold jobs_refuse_threshold warn_threshold max_decisions unavailable projects")

// GuideSettings are the keys of .laneboss/shared/services/guide.toml. Every key is optional.
type GuideSettings struct {
	Enabled       bool     // enabled: false switches the org hook's guard off
	Jobs          bool     // jobs: false disables catalog scoring; baseline policy still applies
	RefuseSet     bool     // retained for configuration compatibility; never grants refusal authority
	JobsRefuseAt  *float64 // legacy setting, validated but not used to refuse ordinary work
	Configuration string   // configuration: the launcher configuration that defines the judge
	Judge         string   // judge: the judge to ask; empty means that none is configured
	RefuseAt      float64  // legacy refuse_threshold: probability cutoff for decided-answer lookup
	WarnAt        float64  // warn_threshold: probability at or above this warns
	MaxDecisions  int      // max_decisions: the most decisions asked about for one call
	OnUnavailable string   // ordinary guidance always warns; legacy "refuse" is accepted as warn
	Projects      []string // projects: the hook considers only decisions of these project labels; empty means any
}

// GuideSettingsError says that guide.toml cannot be used. Its text names the file and the key, never a value.
type GuideSettingsError struct {
	message string
	Field   string
}

func (e *GuideSettingsError) Error() string { return guideSettingsFile + ": " + e.message }

func defaultGuideSettings(history object) GuideSettings {
	return GuideSettings{Enabled: true, Jobs: true, Configuration: str(history["configuration"]), RefuseAt: 0.85, WarnAt: 0.5, MaxDecisions: 5, OnUnavailable: "warn"}
}

func guideKeyName(key string) string {
	text := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, key)
	if runes := []rune(text); len(runes) > 40 {
		return string(runes[:40]) + "..."
	}
	return text
}

func parseGuideSettings(data, history object) (GuideSettings, error) {
	fallback := defaultGuideSettings(history)
	fail := func(format string, args ...any) (GuideSettings, error) {
		message := fmt.Sprintf(format, args...)
		field := strings.Fields(message)[0]
		if strings.HasPrefix(message, "has an unknown key: ") {
			field = strings.TrimPrefix(message, "has an unknown key: ")
		}
		return fallback, &GuideSettingsError{message: message, Field: field}
	}
	names := make([]string, 0, len(data))
	for key := range data {
		names = append(names, key)
	}
	sort.Strings(names)
	for _, key := range names {
		if !guideKeys[key] {
			return fail("has an unknown key: %s", guideKeyName(key))
		}
	}
	s := defaultGuideSettings(history)
	if value, exists := data["jobs"]; exists {
		on, ok := value.(bool)
		if !ok {
			return fail("jobs must be true or false")
		}
		s.Jobs = on
	}
	if v, ok := data["enabled"]; ok {
		on, isBool := v.(bool)
		if !isBool {
			return fail("enabled must be true or false")
		}
		s.Enabled = on
	}
	for _, key := range []string{"configuration", "judge"} {
		if v, ok := data[key]; ok {
			text, isText := v.(string)
			if !isText || !configPattern.MatchString(text) {
				return fail("%s must be a name that matches [a-z0-9][a-z0-9-]{0,31}", key)
			}
			if key == "configuration" {
				s.Configuration = text
			} else {
				s.Judge = text
			}
		}
	}
	for _, key := range []string{"refuse_threshold", "warn_threshold"} {
		if v, ok := data[key]; ok {
			n, isNumber := number(v)
			if !isNumber || n < 0 || n > 1 {
				return fail("%s must be a number from 0 to 1", key)
			}
			if key == "refuse_threshold" {
				s.RefuseAt = n
				s.RefuseSet = true
			} else {
				s.WarnAt = n
			}
		}
	}
	if value, exists := data["jobs_refuse_threshold"]; exists {
		n, ok := number(value)
		if !ok || n < 0 || n > 1 {
			return fail("jobs_refuse_threshold must be a number from 0 to 1")
		}
		s.JobsRefuseAt = &n
	}
	if v, ok := data["max_decisions"]; ok {
		n, isInteger := integer(v)
		if !isInteger || n < 1 || n > 12 {
			return fail("max_decisions must be a whole number from 1 to 12")
		}
		s.MaxDecisions = int(n)
	}
	if v, ok := data["unavailable"]; ok {
		text, isText := v.(string)
		if !isText || (text != "warn" && text != "refuse") {
			return fail("unavailable must be \"warn\" or \"refuse\"")
		}
		s.OnUnavailable = "warn"
	}
	if v, ok := data["projects"]; ok {
		list, isList := v.([]any)
		if !isList || len(list) > 32 {
			return fail("projects must be a list of at most 32 project labels")
		}
		for _, item := range list {
			text, isText := item.(string)
			if !isText || strings.TrimSpace(text) == "" || utf8.RuneCountInString(text) > 128 || strings.IndexFunc(text, unicode.IsControl) >= 0 {
				return fail("projects must hold project labels: nonempty text of at most 128 characters")
			}
			s.Projects = append(s.Projects, text)
		}
	}
	if s.WarnAt > s.RefuseAt {
		return fail("warn_threshold must not be above refuse_threshold")
	}
	if s.JobsRefuseAt != nil && s.WarnAt > *s.JobsRefuseAt {
		return fail("jobs_refuse_threshold must not be below warn_threshold")
	}
	if s.Judge != "" && s.Configuration == "" {
		return fail("judge needs configuration (or a configuration in the org's history settings)")
	}
	return s, nil
}

// loadGuideSettings reads guide.toml of the org at HOME. present says whether the file is there at all: a missing file is
// an org that has not set the guard up (the defaults, no error), while a file that is there and cannot be used is an
// error with present true.
func loadGuideSettings(home string, history object) (settings GuideSettings, present bool, err error) {
	defaults := defaultGuideSettings(history)
	path, e := within(filepath.Join(home, filepath.FromSlash(guideSettingsFile)), home)
	if e != nil {
		return defaults, true, &GuideSettingsError{message: "the file path leaves the org", Field: "path"}
	}
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return defaults, false, nil
	}
	if e != nil || !info.Mode().IsRegular() {
		return defaults, true, &GuideSettingsError{message: "is not a readable regular file", Field: "file"}
	}
	data, e := readTOML(path)
	if e != nil {
		return defaults, true, &GuideSettingsError{message: "is not valid TOML text of at most 64 KiB", Field: "syntax"}
	}
	settings, err = parseGuideSettings(data, history)
	return settings, true, err
}

// Guide is an org's decision store, read for guidance, with the settings of the dial.
type Guide struct {
	Settings    GuideSettings
	SettingsErr error // non-nil for unusable settings; defaults retain a valid explicit unavailable policy
	// Present says whether guide.toml is there at all. An org with no guide.toml has not set the guard up, and the hook
	// leaves its calls to the org's rules alone.
	Present bool
	org     *orgContext
	Capped  bool // another applicable record exists beyond the scoped 1,000-row cap
}

// OpenGuide reads the org's history settings and guide.toml. An error means that the org's history settings cannot be
// read, so the store cannot be located. A guide.toml that cannot be used is not an error here but SettingsErr: a brief
// needs only the store, while the org hook applies the unavailable policy with a field notice.
func OpenGuide(directory string) (*Guide, error) {
	o, e := openOrg(directory)
	if e != nil {
		return nil, e
	}
	g := &Guide{org: o}
	g.Settings, g.Present, g.SettingsErr = loadGuideSettings(o.home, o.history)
	return g, nil
}

// ReadGuideSettings reads only guide.toml of the org at DIRECTORY, for a caller that could not open the org because its
// history settings are unreadable: the dial's `unavailable` setting is still known then, and the caller can honour it.
func ReadGuideSettings(directory string) (GuideSettings, bool, error) {
	given, e := realPath(directory)
	if e != nil {
		return GuideSettings{}, false, e
	}
	home, root := filepath.Join(given, ".laneboss"), given
	if filepath.Base(given) == ".laneboss" {
		home, root = given, filepath.Dir(given)
	}
	if home, e = within(home, root); e != nil {
		return GuideSettings{}, false, e
	}
	// A judge named with no configuration of its own would take it from the history settings, which cannot be read here:
	// a placeholder stands in, because the caller asks nobody.
	return loadGuideSettings(home, object{"configuration": "history-unreadable"})
}

// HasStore says whether the org has a decision store at its configured place. A missing store is no decisions.
func (g *Guide) HasStore() bool {
	info, e := os.Stat(g.org.db)
	return e == nil && info.Mode().IsRegular()
}

// GuideDecision is one recorded decision that can guide an agent.
type GuideDecision struct {
	ID, Kind, Project, Question, Answer, AnsweredAt, Instance string
	ExamplesNotOK, ExamplesOK                                 []string
	Level                                                     int // 0 when the record has no level
}

type guideFilter struct {
	projects  []string
	instance  string
	level     int
	allLevels bool
}

// read returns the in-force decisions of the guiding kinds that keep accepts, newest first. A record is checked whole
// before it is used, and a record whose scope.valid_until has passed is not in force.
func (g *Guide) read(filter guideFilter) ([]GuideDecision, error) {
	db, e := openStore(g.org.db, true, 2*time.Second)
	if e != nil {
		return nil, e
	}
	defer db.Close()
	marks := strings.TrimSuffix(strings.Repeat("?,", len(guideKinds)), ",")
	args := make([]any, 0, len(guideKinds)+1)
	for _, kind := range guideKinds {
		args = append(args, kind)
	}
	where := "status = 'in_force' AND kind IN (" + marks + ")"
	if len(filter.projects) > 0 {
		where += " AND project IN (" + strings.TrimSuffix(strings.Repeat("?,", len(filter.projects)), ",") + ")"
		for _, project := range filter.projects {
			args = append(args, project)
		}
	}
	if !filter.allLevels {
		where += " AND (COALESCE(level, 0) = 0 OR level = ?"
		args = append(args, filter.level)
		if filter.instance != "" {
			where += " OR instance = ?"
			args = append(args, filter.instance)
		}
		where += ")"
	}
	args = append(args, guideStoreRows+1)
	rows, e := readRows(context.Background(), db, "SELECT * FROM records WHERE "+where+" ORDER BY answered_utc DESC, id LIMIT ?", args...)
	if e != nil {
		return nil, e
	}
	now := time.Now()
	found := []GuideDecision{}
	g.Capped = len(rows) > guideStoreRows
	if g.Capped {
		rows = rows[:guideStoreRows]
	}
	for _, row := range rows {
		level, _ := integer(row["level"])
		record, e := checkedRecord(row)
		if e != nil {
			return nil, e
		}
		if until := str(obj(record["scope"])["valid_until"]); until != "" {
			if t, e := timestamp(until, "scope.valid_until"); e == nil && t.Before(now) {
				continue
			}
		}
		found = append(found, GuideDecision{
			ID: str(record["id"]), Kind: str(record["kind"]), Project: str(record["project"]),
			Question: str(obj(record["question"])["text"]), Answer: str(obj(record["answer"])["verbatim"]),
			AnsweredAt: str(record["answered_at"]), Instance: str(row["instance"]), Level: int(level),
		})
	}
	return found, nil
}

// HookDecisions are the decisions that bear on a tool call of the org instance NAME at LEVEL: those with no level, those
// of this level and those scoped to this instance, restricted to the projects setting when it is not empty.
func (g *Guide) HookDecisions(level int, name string) ([]GuideDecision, error) {
	return g.read(guideFilter{projects: g.Settings.Projects, level: level, instance: name})
}

// BriefSectionFor returns the section of recorded decisions for a lane brief or a turn message of PROJECT at LEVEL in
// the org at DIRECTORY, ready to go before the task. It is empty when the org has no store or no decision applies. A lane
// with no project gets the decisions of every project, or of the project labels that guide.toml's projects names. It
// never fails the brief: a store that cannot be read becomes a visible notice in its place.
// holdsCredential is the caller's own credential detector, applied to every quoted text besides this package's.
func BriefSectionFor(directory, project string, level int, holdsCredential func(string) bool) string {
	if faults.Get("guide-omit-section").Point != "" {
		_ = faults.Reach("guide-omit-section")
		return ""
	}
	g, e := OpenGuide(directory)
	if e != nil {
		return guideUnreadable(project, e)
	}
	if !g.HasStore() {
		return ""
	}
	projects := g.Settings.Projects
	if project != "" {
		projects = []string{project}
	}
	decisions, e := g.read(guideFilter{projects: projects, level: level})
	if e != nil {
		return guideUnreadable(project, e)
	}
	if len(decisions) == 0 {
		return ""
	}
	section := guideSection(project, level, g.Settings.Projects, decisions, holdsCredential)
	if holdsCredential != nil && holdsCredential(section) {
		// A brief that holds a credential shape is refused whole; a recorded decision must never break a lane start.
		return fmt.Sprintf("%s\n\nRecorded decisions apply to this lane, but their text could not be shown here because it looks like a credential. Before you act on anything that the owner may already have decided, ask your supervisor which decisions apply.\n\n", guideHeading)
	}
	return section
}

func guideUnreadable(project string, e error) string {
	return fmt.Sprintf("%s\n\nThe org's decision store could not be read (error code %d), so no recorded decision is shown here. Before you act on anything that the owner may already have decided%s, ask your supervisor which decisions apply.\n\n", guideHeading, errorCode(e), guideFor(project))
}

func guideFor(project string) string {
	if project == "" {
		return ""
	}
	return " for project " + project
}

func guideSection(project string, level int, labels []string, decisions []GuideDecision, holds func(string) bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", guideHeading)
	scope := "Project " + project
	if project == "" {
		scope = "This lane has no project, so the decisions of every project apply to it"
		if len(labels) > 0 {
			scope = "This lane has no project, so the decisions of the projects " + strings.Join(labels, ", ") + " apply to it"
		}
	}
	fmt.Fprintf(&b, "%s (level L%d). These are the owner's recorded decisions, and they bind this lane until the owner supersedes them. Follow each one. Do not ask a question that one of them already answers: use its answer. Do not run a tool call that conflicts with one: the org hook checks applicable calls against them and gives advisory context, quoting the decision and its yes probability. A question to your recorded supervisor goes with `laneboss report --ask`, or `laneboss lane send --ask` for a permitted lane; one that these decisions already answer comes back answered and is not sent.\n\n", scope, level)
	shown := decisions
	if len(shown) > guideBriefMax {
		shown = shown[:guideBriefMax]
	}
	for _, d := range shown {
		fmt.Fprintf(&b, "- **%s** (%s, answered %s)\n", d.ID, d.Kind, d.AnsweredAt)
		fmt.Fprintf(&b, "  - Decided: \"%s\"\n", guideQuote(d.Answer, guideAnswerBytes, holds))
		fmt.Fprintf(&b, "  - It answered: \"%s\"\n", guideQuote(d.Question, guideQuestionBytes, holds))
	}
	if more := len(decisions) - len(shown); more > 0 {
		option := ""
		if project != "" {
			option = " --project " + project
		}
		fmt.Fprintf(&b, "\n%d more decisions apply and are not shown here; list them with `laneboss decisions search --db <store> \"\" --mode exact%s`.\n", more, option)
	}
	b.WriteString("\n")
	return b.String()
}

// guideQuote puts a text on one line, withholds one that looks like a credential and cuts one that is too long.
func guideQuote(text string, limit int, holds func(string) bool) string {
	text = strings.Join(strings.Fields(text), " ")
	if credentialsInText(text) || (holds != nil && holds(text)) {
		return guideWithheld
	}
	if len(text) > limit {
		text = cutBytes(text, limit) + "…"
	}
	return text
}

// ScreenedEcho prepares a recorded --ask answer. Either unsafe question or
// answer withholds both texts; the caller still learns that the question was
// decided and must ask its supervisor for the usable decision. Clean text keeps
// its exact bytes, as the existing --ask contract requires.
func (d GuideDecision) ScreenedEcho(holds func(string) bool) (GuideDecision, bool) {
	if faults.Get("guide-echo-unscreened").Point != "" {
		if err := faults.Reach("guide-echo-unscreened"); err != nil {
			panic("decision echo mutation marker could not be kept")
		}
		return d, false
	}
	unsafe := func(text string) bool {
		return credentialsInText(text) || (holds != nil && holds(text))
	}
	withheld := unsafe(d.Question) || unsafe(d.Answer)
	for _, field := range []*string{&d.ID, &d.Kind, &d.Project, &d.AnsweredAt, &d.Instance} {
		if unsafe(*field) {
			*field = guideWithheld
			withheld = true
		}
	}
	if withheld {
		d.Question, d.Answer = guideWithheld, guideWithheld
	}
	return d, withheld
}

// SafeEchoLabel screens metadata such as related decision ids before they are
// returned to an asking caller.
func SafeEchoLabel(text string, holds func(string) bool) string {
	if credentialsInText(text) || (holds != nil && holds(text)) {
		return guideWithheld
	}
	return text
}

// Describe renders the decision for an agent: its id, kind and date, its text and the question it answered, each cut.
func (d GuideDecision) Describe(answerBytes, questionBytes int) string {
	return fmt.Sprintf("%s (%s, answered %s): \"%s\" It answered: \"%s\"", d.ID, d.Kind, d.AnsweredAt,
		guideQuote(d.Answer, answerBytes, nil), guideQuote(d.Question, questionBytes, nil))
}

func guideWords(text string) map[string]bool {
	words := map[string]bool{}
	for _, word := range strings.FieldsFunc(text, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) }) {
		word = casefold(word)
		if utf8.RuneCountInString(word) >= 3 && !stopWords[word] {
			words[word] = true
		}
	}
	return words
}

// RankDecisions keeps at most limit of the decisions: those that share the most words with text come first and, among
// equals, the newest (the order they arrive in) comes first.
func RankDecisions(decisions []GuideDecision, text string, limit int) []GuideDecision {
	asked, _ := SelectDecisions(decisions, text, limit)
	return asked
}

// SelectDecisions splits the decisions into the at most limit that are asked about, ranked as RankDecisions does, and
// the rest. The text that ranks them is the agent's own, so the ranking decides only the order of asking: a caller must
// never take a decision that was left out for one that was judged, and the guard reports every one of them.
func SelectDecisions(decisions []GuideDecision, text string, limit int) (asked, left []GuideDecision) {
	type ranked struct {
		decision GuideDecision
		shared   int
	}
	words := guideWords(text)
	rows := make([]ranked, len(decisions))
	for i, d := range decisions {
		shared := 0
		for word := range guideWords(d.Answer + " " + d.Question) {
			if words[word] {
				shared++
			}
		}
		rows[i] = ranked{d, shared}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].shared > rows[j].shared })
	if limit < 0 {
		limit = 0
	}
	for i, row := range rows {
		if i < limit {
			asked = append(asked, row.decision)
		} else {
			left = append(left, row.decision)
		}
	}
	return asked, left
}

// Decided is a recorded decision that already answers a question.
type Decided struct {
	Decision GuideDecision
	Match    string  // "exact": the same question; "judge": the judge scored it at or above the refuse threshold
	Score    float64 // the judge's score; 1 for an exact match
}

// guideSame puts a question in the form in which two questions are the same question: one line, folded, with no
// closing punctuation.
func guideSame(text string) string {
	return strings.TrimRight(casefold(strings.Join(strings.Fields(text), " ")), "?？!！.。 ")
}

// Answer is what a lookup of a question among the recorded decisions found.
type Answer struct {
	Decided *Decided // the decision that already answers the question; nil when none does
	Related []Scored // the decisions that the judge scored from the warn threshold up to the refuse threshold
	// Judge says what became of the judge, so that a question that went unchecked is never taken for one that was
	// checked: "answered" (every ask got a score), "unavailable" (at least one ask got none), "unconfigured" (guide.toml
	// names no judge), "settings-error" (guide.toml cannot be used) or "not-asked" (the same question was found first).
	Judge string
}

// AnswerFor looks for a recorded decision that already answers QUESTION among those of PROJECT and LEVEL (every
// project when PROJECT is empty, every level when LEVEL is 0; a decision with no level applies at every level). The same
// question, compared as guideSame does, is answered at once and needs no judge. Otherwise, when a judge is configured,
// it is asked once for each of the most related decisions: a score at or above the refuse threshold answers the
// question, and the decisions that score between the thresholds come back as related.
func (g *Guide) AnswerFor(question, project string, level int) (Answer, error) {
	answer := Answer{Judge: "unconfigured", Related: []Scored{}}
	if faults.Get("guide-no-echo").Point != "" {
		_ = faults.Reach("guide-no-echo")
		return answer, nil
	}
	if !g.HasStore() {
		return answer, nil
	}
	projects := g.Settings.Projects
	if project != "" {
		projects = []string{project}
	}
	decisions, e := g.read(guideFilter{projects: projects, level: level, allLevels: level == 0})
	if e != nil {
		return answer, e
	}
	if len(decisions) == 0 {
		return answer, nil
	}
	if wanted := guideSame(question); wanted != "" {
		for _, d := range decisions {
			if guideSame(d.Question) == wanted {
				answer.Decided, answer.Judge = &Decided{Decision: d, Match: "exact", Score: 1}, "not-asked"
				return answer, nil
			}
		}
	}
	if g.SettingsErr != nil {
		answer.Judge = "settings-error"
		return answer, nil
	}
	if g.Settings.Judge == "" {
		return answer, nil
	}
	candidates := RankDecisions(decisions, question, g.Settings.MaxDecisions)
	scored := g.JudgeAnswers(candidates, question)
	answer.Judge = "answered"
	var best *Scored
	for i := range scored {
		switch {
		case !scored[i].Answered():
			answer.Judge = "unavailable"
		case scored[i].Band == BandRefuse:
			if best == nil || scored[i].Score > best.Score {
				best = &scored[i]
			}
		case scored[i].Band == BandWarn:
			answer.Related = append(answer.Related, scored[i])
		}
	}
	if best != nil {
		answer.Decided = &Decided{Decision: best.Decision, Match: "judge", Score: best.Score}
	}
	return answer, nil
}
