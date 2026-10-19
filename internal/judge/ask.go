package judge

import (
	"context"
	"fmt"
	"os"
	"time"
)

// Text is one named text of a question's subject, given in memory.
type Text struct{ Name, Value string }

// Verdict is what one Ask returned: the judge's probability of YES, or why it gave none.
type Verdict struct {
	Outcome     string  // answered, or timeout, exit, output or not-found: the reasons of docs/judges.md
	Probability float64 // the probability of YES; only meaningful when Outcome is answered
	Model       string  // what answered; empty when the judge did not say
	Detail      string  // one short line saying why there is no answer; empty when answered
	// Withheld and Cut name the subject texts that the judge was not given whole. A text that looks like a credential is
	// replaced by a placeholder before anything is sent, and a text longer than the limit is cut: the judge then
	// answered about something other than what the caller meant, so a caller that acts on the probability must not take
	// it for a score of the whole text.
	Withheld []string
	Cut      []string
}

// Ask asks judge NAME of configuration CONFIGURATION one yes/no question, with the texts in memory, and does exactly what
// `laneboss judge ask` does with them: the credential screening and the cuts, the sent and outcome lines of the egress
// log, the time-out and the process cleanup. A non-nil error means nothing was asked (an unknown judge or
// configuration, a refused name, an egress log that cannot be written); its text never repeats a credential.
func Ask(configuration, name, question, prompt string, subject []Text) (Verdict, error) {
	return AskContext(context.Background(), configuration, name, question, prompt, subject)
}

// AskContext carries one deadline through process execution and both log locks.
func AskContext(ctx context.Context, configuration, name, question, prompt string, subject []Text) (Verdict, error) {
	if err := ctx.Err(); err != nil {
		return Verdict{Outcome: "timeout"}, nil
	}
	return askContext(ctx, configuration, name, question, prompt, subject)
}

// AskWithin is the same TypeSafe request as Ask, with an additional caller
// deadline. It is used by synchronous hooks so a slow judge can never hold a
// runner indefinitely. Zero preserves the configured judge timeout.
func AskWithin(limit time.Duration, configuration, name, question, prompt string, subject []Text) (Verdict, error) {
	ctx := context.Background()
	if limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	return askContext(ctx, configuration, name, question, prompt, subject)
}

// AskTransient uses the same request construction, credential screening and
// judge process as Ask, but omits the egress/state log. It is for read-only
// policy previews such as `org blacklist try`; it never records a decision.
func AskTransient(limit time.Duration, configuration, name, question, prompt string, subject []Text) (Verdict, error) {
	return askTransient(limit, configuration, name, question, prompt, subject)
}

func askContext(ctx context.Context, configuration, name, question, prompt string, subject []Text) (Verdict, error) {
	o := options{config: configuration, configSet: true, judge: name, question: question, questionSet: true}
	// An ask made from inside a lane's session is logged under that lane, as `judge ask --lane` would.
	if lane := os.Getenv("LANEBOSS_LANE"); lanePattern.MatchString(lane) {
		o.lane, o.laneSet = lane, true
	}
	c, err := loadConfiguration(o)
	if err != nil {
		return Verdict{}, err
	}
	for _, pair := range []textPair{{"--judge", name}, {"--question", question}} {
		if hasCredential(pair.text) {
			return Verdict{}, refused(pair.name + " looks like a credential and is not used (it is not repeated either); " + nothingAsked)
		}
	}
	if !namePattern.MatchString(name) {
		return Verdict{}, refused("the judge name must match [a-z0-9][a-z0-9-]{0,31}")
	}
	j, ok := c.judges[name]
	if !ok {
		return Verdict{}, refused(fmt.Sprintf("configuration %s has no judge named %s; its judges are %s", shown(c.name), shown(name), joinNames(sortedKeys(c.judges))))
	}
	subjects := make([]textPair, 0, len(subject))
	for _, text := range subject {
		if hasCredential(text.Name) {
			return Verdict{}, refused("a subject name looks like a credential and is not used (it is not repeated either); " + nothingAsked)
		}
		subjects = append(subjects, textPair{text.Name, text.Value})
	}
	r, err := buildRequest(o, prompt, subjects)
	if err != nil {
		return Verdict{}, err
	}
	result, detail, interrupted, err := askJudgeContext(ctx, c, o, j, r)
	if err != nil {
		return Verdict{}, err
	}
	if interrupted {
		return Verdict{Outcome: "exit", Detail: "interrupted", Withheld: r.withheld, Cut: r.cut}, nil
	}
	verdict := Verdict{Outcome: result.Outcome, Detail: detail, Withheld: r.withheld, Cut: r.cut}
	if result.Outcome == "answered" && result.Probability != nil {
		verdict.Probability = *result.Probability
		if result.Model != nil {
			verdict.Model = *result.Model
		}
	}
	return verdict, nil
}

func askTransient(limit time.Duration, configuration, name, question, prompt string, subject []Text) (Verdict, error) {
	o := options{config: configuration, configSet: true, judge: name, question: question, questionSet: true}
	c, err := loadConfiguration(o)
	if err != nil {
		return Verdict{}, err
	}
	for _, pair := range []textPair{{"--judge", name}, {"--question", question}} {
		if hasCredential(pair.text) {
			return Verdict{}, refused(pair.name + " looks like a credential and is not used (it is not repeated either); " + nothingAsked)
		}
	}
	if !namePattern.MatchString(name) {
		return Verdict{}, refused("the judge name must match [a-z0-9][a-z0-9-]{0,31}")
	}
	j, ok := c.judges[name]
	if !ok {
		return Verdict{}, refused(fmt.Sprintf("configuration %s has no judge named %s; its judges are %s", shown(c.name), shown(name), joinNames(sortedKeys(c.judges))))
	}
	subjects := make([]textPair, 0, len(subject))
	for _, text := range subject {
		if hasCredential(text.Name) {
			return Verdict{}, refused("a subject name looks like a credential and is not used (it is not repeated either); " + nothingAsked)
		}
		subjects = append(subjects, textPair{text.Name, text.Value})
	}
	r, err := buildRequest(o, prompt, subjects)
	if err != nil {
		return Verdict{}, err
	}
	reason, status, output, stderr, _ := runCommandWithin(j.command, r.data, j.seconds, limit, nil)
	var parsed answer
	if reason == "" {
		if status != 0 {
			reason = "exit"
		} else if found, ok := readAnswer(output); ok {
			reason = "answered"
			parsed = found
		} else {
			reason = "output"
		}
	}
	verdict := Verdict{Outcome: reason, Withheld: r.withheld, Cut: r.cut}
	if reason == "answered" && parsed.p != nil {
		verdict.Probability = *parsed.p
		verdict.Model = stringValue(parsed.model)
	}
	if reason != "answered" {
		verdict.Detail = transientDetail(reason, status, stderr)
	}
	return verdict, nil
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func transientDetail(reason string, status int, stderr []byte) string {
	if reason == "timeout" {
		return "judge timed out"
	}
	if reason == "not-found" {
		return "judge was not found"
	}
	if reason == "output" {
		return "judge output was not an answer"
	}
	if status != 0 {
		return fmt.Sprintf("judge exited with status %d", status)
	}
	return explanation(stderr)
}

func joinNames(names []string) string {
	text := ""
	for i, name := range names {
		if i > 0 {
			text += ", "
		}
		text += name
	}
	return text
}
