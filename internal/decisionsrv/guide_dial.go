package decisionsrv

import (
	"context"
	"fmt"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/guardtime"
	"laneboss.io/laneboss/internal/judge"
)

// These Nouls estimate the probability of a binary conflict or already-answered
// proposition. A value near 0.5 is uncertainty, not medium conflict severity.
// Thresholds are policy probability cuts; they need domain calibration.

const (
	// ConflictQuestion and AnswersQuestion are the question identifiers of the two asks that the guide makes of a judge.
	ConflictQuestion = "decision.conflicts"
	AnswersQuestion  = "decision.answers"
	conflictPrompt   = "An owner's recorded decision is in force, and an agent is about to run the action. Does running the action conflict with the decision: does it do what the decision forbids, leave undone what it requires, or contradict it? Answer yes only for a real conflict; an action that has nothing to do with the decision is not a conflict. The decision is the text named `decision`, and the action is the text named `action`. When the action starts with a line such as `[part 2 of 3 of the call]`, it is one part of a longer call, and the part you are given is the one to judge."
	answersPrompt    = "An agent asks the question. Does the recorded decision already answer that question, so that asking it again would only repeat a matter that the owner has settled? Answer yes only when the decision settles what the question asks. The decision is the text named `decision`, and the question is the text named `question`."
)

// Band says what the dial does with a score.
type Band int

const (
	BandNone   Band = iota // below warn_threshold: nothing
	BandWarn               // advisory probability at or above warn_threshold
	BandRefuse             // legacy name for the high-probability lookup band; ordinary guidance still only warns
)

func (b Band) String() string {
	switch b {
	case BandRefuse:
		return "refuse"
	case BandWarn:
		return "warn"
	}
	return "none"
}

// BandOf preserves the high-probability cutoff used by decided-answer lookup.
// Hook callers must treat both nonzero bands as advice, not refusal authority.
func (s GuideSettings) BandOf(score float64) Band {
	if faults.Get("guide-ignore-thresholds").Point != "" {
		_ = faults.Reach("guide-ignore-thresholds")
		return BandNone
	}
	if score >= s.RefuseAt {
		return BandRefuse
	}
	if score >= s.WarnAt {
		if faults.Get("guide-no-warning").Point != "" {
			_ = faults.Reach("guide-no-warning")
			return BandNone
		}
		return BandWarn
	}
	return BandNone
}

// Scored is one decision with what the judge said about it.
type Scored struct {
	Decision GuideDecision
	Score    float64
	Band     Band
	// Outcome is "answered", or why there is no score: timeout, exit, output, not-found, refused or unconfigured (the
	// judge gave none); withheld or cut (the judge was not given the whole text, a credential screen or a length limit
	// having changed it, so its probability says nothing about the call); partial (the call is longer than the windows
	// that are read); not-asked (max_decisions left the decision out).
	Outcome string
}

const (
	// One ask carries at most askWindow characters of the call, because the judge machinery cuts a text at 4,000 and
	// the part that it cuts off is never read. A longer call is read in windows that overlap by askOverlap characters,
	// so that an operation on a boundary is whole in one of them, and at most askWindows of them: what lies beyond is
	// not read, and the call is then not taken for scored.
	askWindow  = 3500
	askOverlap = 300
	askWindows = 3
)

// ReadLimit is the most characters of one call that the guard reads: askWindows windows that overlap by askOverlap.
func ReadLimit() int { return askWindow + (askWindows-1)*(askWindow-askOverlap) }

// ActionWindows splits the text of a call into the windows that one ask each carries. beyond says that the call is
// longer than the windows that are read, so that part of it was never given to a judge.
func ActionWindows(text string) (windows []string, beyond bool) {
	runes := []rune(text)
	if len(runes) <= askWindow {
		return []string{text}, false
	}
	step := askWindow - askOverlap
	total := 1 + (len(runes)-askWindow+step-1)/step
	for i := 0; i < total && i < askWindows; i++ {
		start := i * step
		end := start + askWindow
		if end > len(runes) {
			end = len(runes)
		}
		windows = append(windows, fmt.Sprintf("[part %d of %d of the call]\n%s", i+1, total, string(runes[start:end])))
	}
	return windows, total > askWindows
}

// Answered says whether the judge gave a score.
func (s Scored) Answered() bool { return s.Outcome == "answered" }

// SubjectText renders the decision for a judge: its id first, then its text and the question it answered.
func (d GuideDecision) SubjectText() string {
	text := fmt.Sprintf("%s (%s): %s\nThe question it answered: %s", d.ID, d.Kind, d.Answer, d.Question)
	if len(d.ExamplesNotOK) > 0 {
		text += "\nExamples not OK: " + strings.Join(d.ExamplesNotOK, " | ")
	}
	if len(d.ExamplesOK) > 0 {
		text += "\nExamples OK: " + strings.Join(d.ExamplesOK, " | ")
	}
	return text
}

func conflictSubject(d GuideDecision, action string) []judge.Text {
	return []judge.Text{{Name: "decision", Value: d.SubjectText()}, {Name: "action", Value: action}}
}

func answersSubject(d GuideDecision, question string) []judge.Text {
	return []judge.Text{{Name: "decision", Value: d.SubjectText()}, {Name: "question", Value: question}}
}

// JudgeConflicts asks one Noul per candidate/window in a single request whether
// running ACTION conflicts with the decision. The batch uses the judge machinery: it
// is screened for credentials and logged in the egress log. A candidate that has no score of the whole call comes back
// with its outcome: the judge gave no answer, a text was withheld or cut, or the call is longer than what is read. A
// Candidate scores are advisory; refusal authority remains with the org blacklist.
func (g *Guide) JudgeConflicts(candidates []GuideDecision, action string, parents ...context.Context) []Scored {
	var parent context.Context
	if len(parents) > 0 {
		parent = parents[0]
	}
	ctx, cancel := guideContext(parent, 0)
	defer cancel()
	return g.judgeConflictsContext(ctx, candidates, action)
}

// JudgeConflictsWithin is the bounded form used by the synchronous org hook.
// A zero duration preserves the regular decision-guide timeout.
func (g *Guide) JudgeConflictsWithin(candidates []GuideDecision, action string, limit time.Duration) []Scored {
	ctx, cancel := guideContext(nil, limit)
	defer cancel()
	return g.judgeConflictsContext(ctx, candidates, action)
}

func (g *Guide) judgeConflictsContext(ctx context.Context, candidates []GuideDecision, action string) []Scored {
	windows, beyond := ActionWindows(action)
	if faults.Get("guide-head-only").Point != "" && (len(windows) > 1 || beyond) {
		// The mutant: only the head of a long call is judged, and nothing says that the rest was never read.
		_ = faults.Reach("guide-head-only")
		windows, beyond = windows[:1], false
	}
	return g.askBatch(ctx, ConflictQuestion, conflictPrompt, candidates, windows, beyond, false)
}

// JudgeAnswers asks the configured judge in one batch whether each decision already answers
// QUESTION, in the same way as JudgeConflicts. A question that is cut or withheld is not scored.
func (g *Guide) JudgeAnswers(candidates []GuideDecision, question string, parents ...context.Context) []Scored {
	var parent context.Context
	if len(parents) > 0 {
		parent = parents[0]
	}
	ctx, cancel := guideContext(parent, 0)
	defer cancel()
	return g.judgeAnswersContext(ctx, candidates, question)
}

// JudgeAnswersWithin is the bounded form used by the synchronous org hook.
func (g *Guide) JudgeAnswersWithin(candidates []GuideDecision, question string, limit time.Duration) []Scored {
	ctx, cancel := guideContext(nil, limit)
	defer cancel()
	return g.judgeAnswersContext(ctx, candidates, question)
}

func (g *Guide) judgeAnswersContext(ctx context.Context, candidates []GuideDecision, question string) []Scored {
	return g.askBatch(ctx, AnswersQuestion, answersPrompt, candidates, []string{question}, false, false)
}

// BlacklistCandidate is a blacklist entry presented to the same TypeSafe dial
// as a recorded decision. Decision and Job are references used by callers to
// decide whether a scored guide item is merely guidance or a blocking entry.
type BlacklistCandidate struct {
	ID, Description, Decision, Job string
	ExamplesNotOK, ExamplesOK      []string
}

const maxBlacklistCandidates = 12

func blacklistDecision(candidate BlacklistCandidate) GuideDecision {
	return GuideDecision{ID: candidate.ID, Kind: "blacklist", Answer: candidate.Description,
		Question: "This blacklist entry describes an action the org does not allow.",
		Instance: candidate.Decision, Project: candidate.Job, ExamplesNotOK: candidate.ExamplesNotOK, ExamplesOK: candidate.ExamplesOK}
}

func rankBlacklistCandidates(candidates []BlacklistCandidate, action string) (asked, left []BlacklistCandidate) {
	decisions := make([]GuideDecision, len(candidates))
	byID := map[string][]BlacklistCandidate{}
	for index, candidate := range candidates {
		decisions[index] = blacklistDecision(candidate)
		byID[candidate.ID] = append(byID[candidate.ID], candidate)
	}
	ranked, omitted := SelectDecisions(decisions, action, maxBlacklistCandidates)
	take := func(decision GuideDecision) BlacklistCandidate {
		queue := byID[decision.ID]
		if len(queue) == 0 {
			return BlacklistCandidate{ID: decision.ID, Description: decision.Answer, Decision: decision.Instance, Job: decision.Project,
				ExamplesNotOK: decision.ExamplesNotOK, ExamplesOK: decision.ExamplesOK}
		}
		candidate := queue[0]
		byID[decision.ID] = queue[1:]
		return candidate
	}
	for _, decision := range ranked {
		asked = append(asked, take(decision))
	}
	for _, decision := range omitted {
		left = append(left, take(decision))
	}
	return asked, left
}

// JudgeBlacklist judges blacklist descriptions through the same request,
// credential screen, windowing and threshold machinery as decision conflicts.
// The question identifier intentionally remains ConflictQuestion so an org's
// TypeSafe adapter has one judged path and one calibration dial.
func (g *Guide) JudgeBlacklist(candidates []BlacklistCandidate, action string) []Scored {
	return g.JudgeBlacklistWithin(candidates, action, 0)
}

func (g *Guide) JudgeBlacklistWithin(candidates []BlacklistCandidate, action string, limit time.Duration) []Scored {
	return g.judgeBlacklist(candidates, action, limit, false)
}

// JudgeBlacklistTransientWithin uses the same dial without writing judge
// egress/state logs. It is the read-only implementation behind `org blacklist
// try`.
func (g *Guide) JudgeBlacklistTransientWithin(candidates []BlacklistCandidate, action string, limit time.Duration) []Scored {
	return g.judgeBlacklist(candidates, action, limit, true)
}

func (g *Guide) judgeBlacklist(candidates []BlacklistCandidate, action string, limit time.Duration, transient bool) []Scored {
	asked, left := rankBlacklistCandidates(candidates, action)
	decisions := make([]GuideDecision, len(asked))
	for index, candidate := range asked {
		decisions[index] = blacklistDecision(candidate)
	}
	windows, beyond := ActionWindows(action)
	if faults.Get("guide-head-only").Point != "" && (len(windows) > 1 || beyond) {
		_ = faults.Reach("guide-head-only")
		windows, beyond = windows[:1], false
	}
	var scored []Scored
	if transient {
		scored = g.askTransientMode(ConflictQuestion, conflictPrompt, decisions, windows, beyond, limit, true)
	} else {
		ctx, cancel := guideContext(nil, limit)
		defer cancel()
		scored = g.askBatch(ctx, ConflictQuestion, conflictPrompt, decisions, windows, beyond, true)
	}
	for _, candidate := range left {
		scored = append(scored, Scored{Decision: blacklistDecision(candidate), Outcome: "not-asked"})
	}
	queues := map[string][]Scored{}
	for _, item := range scored {
		queues[item.Decision.ID] = append(queues[item.Decision.ID], item)
	}
	ordered := make([]Scored, len(candidates))
	for index, candidate := range candidates {
		queue := queues[candidate.ID]
		if len(queue) == 0 {
			ordered[index] = Scored{Decision: blacklistDecision(candidate), Outcome: "not-asked"}
			continue
		}
		ordered[index] = queue[0]
		queues[candidate.ID] = queue[1:]
	}
	return ordered
}

// NotAsked returns the decisions that max_decisions left out, as Scored values with no score and the outcome not-asked,
// so that a caller treats them like any decision that the judge could not score: a call is never allowed silently while
// a decision that applies to it was not judged.
func NotAsked(left []GuideDecision) []Scored {
	if faults.Get("guide-skip-left-out").Point != "" && len(left) > 0 {
		// The mutant: the decisions that were left out vanish, as if they had been judged and found clear.
		_ = faults.Reach("guide-skip-left-out")
		return nil
	}
	out := make([]Scored, len(left))
	for i, d := range left {
		out[i] = Scored{Decision: d, Outcome: "not-asked"}
	}
	return out
}

func guideContext(parent context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if limit <= 0 {
		return context.WithTimeout(parent, guardtime.Timeout)
	}
	return context.WithTimeout(parent, limit)
}

func (g *Guide) askBatch(ctx context.Context, question, prompt string, candidates []GuideDecision, windows []string, beyond, refuseWins bool) []Scored {
	if len(candidates) == 0 || len(windows) == 0 {
		return nil
	}
	parts := make([][]Scored, len(candidates))
	indexes := make([]int, len(candidates))
	decisions := []any{}
	for i, d := range candidates {
		indexes[i] = -1
		parts[i] = make([]Scored, len(windows))
		text := d.SubjectText()
		cut, withheld := judge.ScreenText(text)
		outcome := ""
		switch {
		case withheld:
			outcome = "withheld"
		case cut:
			outcome = "cut"
		default:
			indexes[i] = len(decisions)
			decisions = append(decisions, text)
		}
		for w := range windows {
			parts[i][w] = Scored{Decision: d, Outcome: outcome}
		}
	}
	verdict := judge.BatchVerdict{Outcome: "unconfigured"}
	var err error
	func() {
		if faults.Get("guide-batch-no-recover").Point == "" {
			defer func() {
				if recover() != nil {
					verdict, err = judge.BatchVerdict{Outcome: "refused"}, nil
				}
			}()
		}
		questions := map[string]any{}
		for _, index := range indexes {
			if index < 0 {
				continue
			}
			for w := range windows {
				instructions := strings.ReplaceAll(prompt, "`decision`", fmt.Sprintf("`decisions[%d]`", index))
				instructions = strings.ReplaceAll(instructions, "`action`", fmt.Sprintf("`texts[%d]`", w))
				instructions = strings.ReplaceAll(instructions, "`question`", fmt.Sprintf("`texts[%d]`", w))
				yes, no := "Running the specified action contradicts the specified recorded decision.", "The action is consistent with, or unrelated to, the specified decision."
				if question == AnswersQuestion {
					yes, no = "The specified decision settles the specified question.", "The decision leaves the specified question unanswered or is unrelated."
				}
				// IDs retain candidate identity while paths index only clean state.
				questions[fmt.Sprintf("d%d-w%d", index, w)] = map[string]any{"type": "noul", "instructions": instructions,
					"criteria": map[string]any{"true": yes, "false": no}}
			}
		}
		if g.Settings.Judge == "" || len(questions) == 0 {
			return
		}
		state := map[string]any{"decisions": decisions, "texts": windows}
		verdict, err = judge.AskNoulsContext(ctx, g.Settings.Configuration, g.Settings.Judge, question, state, questions)
		if verdict.Outcome == "withheld" && faults.Get("guide-withheld-scores").Point != "" {
			// Mutation: ask about placeholders and wrongly treat that answer as
			// coverage of the original text. No credential goes to the adapter.
			_ = faults.Reach("guide-withheld-scores")
			hidden := make([]string, len(windows))
			for i := range hidden {
				hidden[i] = "[withheld]"
			}
			state["texts"] = hidden
			verdict, err = judge.AskNoulsContext(ctx, g.Settings.Configuration, g.Settings.Judge, question, state, questions)
		}
	}()
	if err != nil {
		verdict.Outcome = "refused"
	}
	if ctx.Err() != nil {
		verdict.Outcome = "timeout"
	}
	for i, index := range indexes {
		if index < 0 {
			continue
		}
		for w := range windows {
			s := Scored{Decision: candidates[i], Outcome: verdict.Outcome}
			if verdict.Outcome == "answered" {
				p, exists := verdict.Probabilities[fmt.Sprintf("d%d-w%d", index, w)]
				if exists {
					s.Score, s.Band = p, g.Settings.BandOf(p)
				} else {
					s.Outcome = "output"
				}
			}
			parts[i][w] = s
		}
	}
	out := make([]Scored, len(candidates))
	for i := range candidates {
		out[i] = combineWindows(candidates[i], parts[i], beyond, refuseWins)
	}
	return out
}

// combineWindows retains the strongest yes probability only when every window
// was answered and the entire bounded call was read. Uncovered text remains
// unscored even when a covered window had a high probability.
func combineWindows(d GuideDecision, parts []Scored, beyond, refuseWins bool) Scored {
	best := Scored{Decision: d}
	missing := ""
	for _, part := range parts {
		if !part.Answered() {
			if missing == "" {
				missing = part.Outcome
			}
			continue
		}
		if !best.Answered() || part.Score > best.Score {
			best = part
		}
	}
	if refuseWins && best.Answered() && best.Band == BandRefuse {
		return best
	}
	switch {
	case missing != "":
		return Scored{Decision: d, Outcome: missing}
	case beyond:
		return Scored{Decision: d, Outcome: "partial"}
	case !best.Answered():
		return Scored{Decision: d, Outcome: "refused"}
	}
	return best
}
func (g *Guide) askTransientMode(question, prompt string, candidates []GuideDecision, windows []string, beyond bool, limit time.Duration, refuseWins bool) []Scored {
	parts := make([][]Scored, len(candidates))
	for i := range candidates {
		parts[i] = make([]Scored, len(windows))
		for w := range windows {
			parts[i][w] = g.askOne(question, prompt, candidates[i], conflictSubject(candidates[i], windows[w]), limit, true)
		}
	}
	out := make([]Scored, len(candidates))
	for i := range candidates {
		out[i] = combineWindows(candidates[i], parts[i], beyond, refuseWins)
	}
	return out
}
func (g *Guide) askOne(question, prompt string, d GuideDecision, subject []judge.Text, limit time.Duration, transient bool) (s Scored) {
	s = Scored{Decision: d}
	if g.Settings.Judge == "" {
		s.Outcome = "unconfigured"
		return s
	}
	defer func() {
		if recover() != nil {
			s = Scored{Decision: d, Outcome: "refused"}
		}
	}()
	var verdict judge.Verdict
	var e error
	if transient {
		verdict, e = judge.AskTransient(limit, g.Settings.Configuration, g.Settings.Judge, question, prompt, subject)
	} else if limit > 0 {
		verdict, e = judge.AskWithin(limit, g.Settings.Configuration, g.Settings.Judge, question, prompt, subject)
	} else {
		verdict, e = judge.Ask(g.Settings.Configuration, g.Settings.Judge, question, prompt, subject)
	}
	if e != nil {
		s.Outcome = "refused"
		return s
	}
	s.Outcome = verdict.Outcome
	if verdict.Outcome != "answered" {
		return s
	}
	// The judge's probability is about the texts it was given. A text that looks like a credential is replaced by a
	// placeholder, and one that is too long is cut: the judge then scored something other than the call, and a low
	// probability would read as a clean call that nobody had seen.
	switch {
	case len(verdict.Withheld) > 0 && faults.Get("guide-withheld-scores").Point != "":
		// The mutant: the answer about the placeholder is taken for a score of the call.
		_ = faults.Reach("guide-withheld-scores")
	case len(verdict.Withheld) > 0:
		s.Outcome = "withheld"
		return s
	case len(verdict.Cut) > 0:
		s.Outcome = "cut"
		return s
	}
	s.Score = verdict.Probability
	s.Band = g.Settings.BandOf(verdict.Probability)
	return s
}
