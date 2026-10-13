package decisionsrv

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/decisions/jsonout"
)

const choiceQuestion = "history.owner-decision"
const choicePrompt = "Classify the human message as exactly one Choice: strong-decision (an explicit binding decision or instruction), preference (a nonbinding wish), question (a request for information, including proposals phrased as questions), or other. Return JSON with choice and score (confidence from 0 to 1), optional model and request identifiers. Only name an optional supersedes case id from prior_decisions when this message explicitly overrides it. Preserve the distinction between a question and a decision."

var choices = []string{"strong-decision", "preference", "question", "other"}
var discordSource = regexp.MustCompile(`^discord:[^:]+:([0-9]{17,20})$`)

func sourceTime(source, path, override string) (string, error) {
	if override != "" {
		_, e := timestamp(override, "source time")
		return override, e
	}
	if m := discordSource.FindStringSubmatch(source); len(m) > 0 {
		value, e := strconv.ParseUint(m[1], 10, 64)
		if e != nil {
			return "", invalid("invalid source time")
		}
		milliseconds := int64(value>>22) + 1420070400000
		return time.UnixMilli(milliseconds).UTC().Format("2006-01-02T15:04:05.000000+00:00"), nil
	}
	if stamp := stampInText.FindString(source); stamp != "" {
		_, e := timestamp(stamp, "source time")
		return stamp, e
	}
	info, e := os.Stat(path)
	if e != nil {
		return "", invalid("cannot read owner message source time")
	}
	return info.ModTime().UTC().Format("2006-01-02T15:04:05.000000+00:00"), nil
}
func decisionThresholds(o *orgContext) (float64, float64, error) {
	strong, review := 0.85, 0.6
	var ok bool
	if v, exists := o.history["decision_threshold"]; exists {
		strong, ok = number(v)
		if !ok {
			return 0, 0, invalid("decision thresholds must be finite numbers")
		}
	}
	if v, exists := o.history["review_threshold"]; exists {
		review, ok = number(v)
		if !ok {
			return 0, 0, invalid("decision thresholds must be finite numbers")
		}
	}
	if review < 0 || review >= strong || strong > 1 {
		return 0, 0, invalid("decision thresholds must satisfy 0 <= review < strong <= 1")
	}
	return strong, review, nil
}
func choiceAnswer(data []byte) (object, error) {
	v, e := parseJSON(data)
	if e != nil {
		return nil, e
	}
	m := obj(v)
	if e = unknown(m, "choice score model request supersedes", "judge Choice"); e != nil {
		return nil, e
	}
	if !hasString(choices, str(m["choice"])) {
		return nil, invalid("judge did not return a documented Choice")
	}
	score, ok := number(m["score"])
	if !ok || score < 0 || score > 1 {
		return nil, invalid("judge Choice score must be between zero and one")
	}
	// Check the literal decimal too: rounding an out-of-range score to 1.0 cannot
	// turn an invalid classification into a binding decision.
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var raw map[string]any
	if decoder.Decode(&raw) != nil {
		return nil, invalid("invalid judge Choice")
	}
	literal, ok := raw["score"].(json.Number)
	if !ok {
		return nil, invalid("invalid judge Choice score")
	}
	exact, ok := new(big.Rat).SetString(string(literal))
	if !ok || exact.Sign() < 0 || exact.Cmp(big.NewRat(1, 1)) > 0 {
		return nil, invalid("judge Choice score must be between zero and one")
	}
	for _, field := range []string{"model", "request"} {
		if m[field] != nil && (!idPattern.MatchString(str(m[field])) || credentialsInText(str(m[field]))) {
			return nil, invalid("judge Choice identifiers are invalid")
		}
	}
	if m["supersedes"] != nil && !idPattern.MatchString(str(m["supersedes"])) {
		return nil, invalid("judge supersedes must be a case id")
	}
	return object{"choice": m["choice"], "score": score, "model": m["model"], "request": m["request"], "supersedes": m["supersedes"]}, nil
}
func screenedChoice(text, source, prior string) ([]byte, []string, []string, error) {
	subject := object{}
	withheld, cut := []string{}, []string{}
	for _, entry := range []struct{ name, text string }{{"message", text}, {"source", source}, {"prior_decisions", prior}} {
		value := entry.text
		if credentialsInText(value) {
			value = "[withheld]"
			withheld = append(withheld, entry.name)
		} else if runes := []rune(value); len(runes) > 4000 {
			value = string(runes[:4000])
			if credentialsInText(value) {
				value = "[withheld]"
				withheld = append(withheld, entry.name)
			} else {
				cut = append(cut, entry.name)
			}
		}
		subject[entry.name] = value
	}
	if hasString(withheld, "message") || hasString(withheld, "source") || hasString(cut, "message") {
		return nil, nil, nil, invalid("owner text/source was withheld or cut by judge screening; nothing is captured")
	}
	request := object{"laneboss_judge": 1, "question": choiceQuestion, "kind": "choice", "prompt": choicePrompt, "subject": subject, "choices": choices}
	if len(withheld) > 0 {
		request["withheld"] = withheld
	}
	if len(cut) > 0 {
		request["cut"] = cut
	}
	serial, e := canonical(request)
	return []byte(serial + "\n"), withheld, cut, e
}
func validateJudgeLine(m object) error {
	if m == nil {
		return invalid("invalid judge egress line")
	}
	event := str(m["event"])
	fields := ""
	if event == "sent" {
		fields = "at ask event judge question lane request_sha256 request_bytes withheld cut"
	} else if event == "outcome" {
		fields = "at ask event outcome probability model request duration_ms"
	} else {
		return invalid("invalid judge egress event")
	}
	set := wordsSet(fields)
	if len(set) != len(m) {
		return invalid("invalid judge egress fields")
	}
	for k := range m {
		if !set[k] {
			return invalid("invalid judge egress fields")
		}
	}
	if !storeIDPattern.MatchString(str(m["ask"])) || !recordedAtPattern.MatchString(str(m["at"])) {
		return invalid("invalid judge egress identity")
	}
	if _, e := timestamp(m["at"], "judge at"); e != nil {
		return e
	}
	if event == "sent" {
		if !configPattern.MatchString(str(m["judge"])) || !regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`).MatchString(str(m["question"])) || len(str(m["question"])) > 64 || (m["lane"] != nil && !lanePattern.MatchString(str(m["lane"]))) || !hashPattern.MatchString(str(m["request_sha256"])) {
			return invalid("invalid judge egress request")
		}
		n, ok := integer(m["request_bytes"])
		if !ok || n < 0 {
			return invalid("invalid judge egress byte count")
		}
		for _, field := range []string{"withheld", "cut"} {
			values, ok := m[field].([]any)
			if !ok {
				return invalid("invalid judge egress screening names")
			}
			for _, v := range values {
				if !regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`).MatchString(str(v)) {
					return invalid("invalid judge egress screening name")
				}
			}
		}
	} else {
		n, ok := integer(m["duration_ms"])
		if !ok || n < 0 {
			return invalid("invalid judge egress duration")
		}
		for _, field := range []string{"model", "request"} {
			if m[field] != nil && (!idPattern.MatchString(str(m[field])) || credentialsInText(str(m[field]))) {
				return invalid("invalid judge egress identifier")
			}
		}
		if m["outcome"] == "answered" {
			n, ok := number(m["probability"])
			if !ok || n < 0 || n > 1 {
				return invalid("invalid judge egress probability")
			}
		} else if !wordsSet("timeout exit output not-found")[str(m["outcome"])] || m["probability"] != nil || m["model"] != nil || m["request"] != nil {
			return invalid("invalid judge egress outcome")
		}
	}
	return nil
}
func judgeEgress(directory string, line object, sending bool) error {
	problem := func() error {
		what := "nothing was asked"
		if !sending {
			what = "the ask was sent and its sending is logged, but its outcome could not be logged"
		}
		return &commandError{7, "egress problem: " + what + ": the egress log cannot be written"}
	}
	lock, err := directoryLock(directory, false)
	if err != nil {
		return problem()
	}
	defer lock.Close()
	path := filepath.Join(directory, "egress.jsonl")
	text := ""
	if _, err := os.Lstat(path); err == nil {
		text, err = readRegular(path, 64<<20)
		if err != nil {
			return problem()
		}
	} else if !os.IsNotExist(err) {
		return problem()
	}
	data, err := jsonout.Line(line)
	if err != nil {
		return problem()
	}
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	if sending {
		trimmed := strings.TrimSpace(text)
		if trimmed != "" {
			last := trimmed
			if at := strings.LastIndexByte(last, '\n'); at >= 0 {
				last = last[at+1:]
			}
			value, err := parseJSON([]byte(last))
			if err != nil || validateJudgeLine(obj(value)) != nil {
				return &commandError{7, "egress problem: nothing was asked: the egress log was not written by this version; move it aside and ask again"}
			}
		}
		unfinished := max(0, strings.Count(text, `"event": "sent"`)-strings.Count(text, `"event": "outcome"`))
		if len(text)+len(data)+1024*(unfinished+1) > 64<<20 {
			return &commandError{7, "egress problem: nothing was asked: the egress log is full; move it aside and ask again"}
		}
	}
	if err = atomicStateFile(directory, "egress.jsonl", append([]byte(text), data...), true); err != nil {
		return problem()
	}
	return nil
}

type judgeBuffer struct {
	cappedBuffer
	cancel context.CancelFunc
}

func (b *judgeBuffer) Write(data []byte) (int, error) {
	n, e := b.cappedBuffer.Write(data)
	if b.exceeded {
		b.cancel()
	}
	return n, e
}
func runChoiceCommand(command []string, data []byte, seconds float64) ([]byte, string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds*float64(time.Second)))
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stdin = bytes.NewReader(data)
	out := &judgeBuffer{cappedBuffer: cappedBuffer{limit: 64 << 10}, cancel: cancel}
	errOut := &judgeBuffer{cappedBuffer: cappedBuffer{limit: 4096}, cancel: cancel}
	cmd.Stdout = out
	cmd.Stderr = errOut
	cmd.WaitDelay = time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if !strings.HasPrefix(name, "LANEBOSS_") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	e := cmd.Run()
	if cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	if out.exceeded || errOut.exceeded {
		return nil, "output"
	}
	if ctx.Err() != nil {
		return nil, "timeout"
	}
	if e != nil {
		if os.IsNotExist(e) {
			return nil, "not-found"
		}
		return nil, "exit"
	}
	return out.Bytes(), "answered"
}
func askChoice(c *privateConfiguration, name, text, source, prior string) (object, error) {
	if !configPattern.MatchString(name) || credentialsInText(name) {
		return nil, invalid("judge name is invalid or looks like a credential")
	}
	judge := obj(obj(c.data["judges"])[name])
	if judge == nil {
		return nil, invalid("configuration has no judge with the requested name")
	}
	raw, ok := judge["command"].([]any)
	if !ok || len(raw) == 0 {
		return nil, invalid("judge command must be a nonempty argument list")
	}
	command := []string{}
	for _, v := range raw {
		argument, ok := v.(string)
		if !ok || argument == "" || strings.ContainsRune(argument, 0) || credentialsInText(argument) {
			return nil, invalid("judge command contains an invalid argument or credential")
		}
		command = append(command, argument)
	}
	seconds := 10.0
	if v, exists := judge["timeout_seconds"]; exists {
		var ok bool
		seconds, ok = number(v)
		if !ok || seconds <= 0 || seconds > 120 {
			return nil, invalid("judge timeout_seconds is invalid")
		}
	}
	data, withheld, cut, e := screenedChoice(text, source, prior)
	if e != nil {
		return nil, e
	}
	if _, e = c.openState(true); e != nil {
		return nil, e
	}
	if e = c.ensureMarker(); e != nil {
		return nil, e
	}
	directory := filepath.Join(c.state, "judges")
	if e = refuseLinks(directory); e != nil {
		return nil, e
	}
	if e = os.MkdirAll(directory, 0700); e != nil {
		return nil, &commandError{7, "egress problem: nothing was asked: cannot open the judge log directory"}
	}
	stateDirectory, e := os.Open(c.state)
	if e != nil {
		return nil, &commandError{7, "egress problem: nothing was asked: cannot open the state directory for sync"}
	}
	e = stateDirectory.Sync()
	closeError := stateDirectory.Close()
	if e != nil || closeError != nil {
		return nil, &commandError{7, "egress problem: nothing was asked: cannot sync the state directory"}
	}
	ask, e := uuidHex()
	if e != nil {
		return nil, e
	}
	sent := object{"at": eventNow(), "ask": ask, "event": "sent", "judge": name, "question": choiceQuestion, "lane": nil, "request_sha256": digest(data), "request_bytes": len(data), "withheld": withheld, "cut": cut}
	if e = judgeEgress(directory, sent, true); e != nil {
		return nil, e
	}
	started := time.Now()
	answerBytes, outcome := runChoiceCommand(command, data, seconds)
	var answer object
	if outcome == "answered" {
		answer, e = choiceAnswer(answerBytes)
		if e != nil {
			outcome = "output"
			answer = nil
		}
	}
	var score, model, request any
	if answer != nil {
		score, model, request = answer["score"], answer["model"], answer["request"]
	}
	line := object{"at": eventNow(), "ask": ask, "event": "outcome", "outcome": outcome, "probability": score, "model": model, "request": request, "duration_ms": int64(time.Since(started).Milliseconds())}
	if e = judgeEgress(directory, line, false); e != nil {
		return nil, e
	}
	result := object{"outcome": outcome, "ask": ask}
	for k, v := range answer {
		result[k] = v
	}
	return result, nil
}
func targetReason(ctx context.Context, w sqlReader, target string, identity object, retryID string) (string, error) {
	rows, e := readRows(ctx, w, "SELECT * FROM records WHERE id = ?", target)
	if e != nil {
		return "", e
	}
	if len(rows) == 0 {
		return "supersedes did not name an active owner decision", nil
	}
	previous, e := checkedRecord(rows[0])
	if e != nil {
		return "", e
	}
	if previous["kind"] != "owner-decision" {
		return "supersedes did not name an active owner decision", nil
	}
	if previous["instance"] != identity["instance"] && !equalValue(previous["level"], identity["level"]) {
		return "supersedes target is outside the new decision's scope", nil
	}
	if previous["status"] != "in_force" && !(retryID != "" && previous["status"] == "superseded" && previous["superseded_by"] == retryID) {
		return "supersedes did not name an active owner decision", nil
	}
	return "", nil
}
func captureDecision(args options) (object, error) {
	o, identity, _, _, e := discover("", args.get("org-dir"), args.get("instance"))
	if e != nil {
		return nil, e
	}
	text, e := readRegular(args.get("text-file"), 64<<10)
	if e != nil {
		return nil, e
	}
	if strings.TrimSpace(text) == "" {
		return nil, invalid("owner message is empty")
	}
	source := args.get("source")
	if strings.TrimSpace(source) == "" {
		return nil, invalid("owner message source is empty")
	}
	authority := args.get("author-authority")
	if authority != "decide" && authority != "inform" {
		return nil, invalid("author-authority must be decide or inform")
	}
	created, e := sourceTime(source, args.get("text-file"), args.get("at"))
	if e != nil {
		return nil, e
	}
	strong, review, e := decisionThresholds(o)
	if e != nil {
		return nil, e
	}
	configName := args.get("config")
	if configName == "" {
		configName = str(o.history["configuration"])
	}
	c, e := loadConfiguration(configName, true)
	if e != nil {
		return nil, e
	}
	judge := args.get("judge")
	if judge == "" {
		judge = str(o.history["judge"])
		if judge == "" {
			judge = "owner-decisions"
		}
	}
	idHash, e := canonicalHash(object{"source": source, "text": text, "instance": identity["instance"]})
	if e != nil {
		return nil, e
	}
	id := "O-" + idHash
	db, e := openStore(o.db, false, 10*time.Second)
	if e != nil {
		return nil, e
	}
	defer db.Close()
	rows, e := readRows(context.Background(), db, "SELECT * FROM records ORDER BY id")
	if e != nil {
		return nil, e
	}
	prior := []storedCase{}
	for _, row := range rows {
		if row["kind"] != "owner-decision" || row["status"] != "in_force" {
			continue
		}
		record, e := checkedRecord(row)
		if e != nil {
			return nil, e
		}
		at, e := timestamp(record["answered_at"], "answered_at")
		if e != nil {
			return nil, e
		}
		prior = append(prior, storedCase{row, record, at})
	}
	sort.Slice(prior, func(i, j int) bool {
		if prior[i].answered.Equal(prior[j].answered) {
			return str(prior[i].record["id"]) < str(prior[j].record["id"])
		}
		return prior[i].answered.Before(prior[j].answered)
	})
	summary := []object{}
	for _, value := range prior[max(0, len(prior)-16):] {
		runes := []rune(str(obj(value.record["answer"])["verbatim"]))
		summary = append(summary, object{"id": value.record["id"], "text": string(runes[:min(150, len(runes))])})
	}
	summaryText, e := canonical(summary)
	if e != nil {
		return nil, e
	}
	verdict, e := askChoice(c, judge, text, source, summaryText)
	if e != nil {
		return nil, e
	}
	receipt := object{"at": utcNow(), "source": source, "source_time": created, "text_sha256": digest(text), "author_authority": authority, "level": identity["level"], "instance": identity["instance"], "event": "classification", "stored": false, "review": false}
	for k, v := range verdict {
		receipt[k] = v
	}
	if e = appendLog(o.captureLog, receipt); e != nil {
		return nil, e
	}
	score, _ := number(verdict["score"])
	if verdict["choice"] == "strong-decision" && authority == "decide" && score >= review {
		record, e := curatedCase(id, "owner-decision", text, source, created, identity, 1)
		if e != nil {
			return nil, e
		}
		target := str(verdict["supersedes"])
		ctx := context.Background()
		var reviewRecord object
		e = writeTransaction(ctx, db, func(w sqlWriter) error {
			existing, e := readRows(ctx, w, "SELECT * FROM records WHERE id = ?", id)
			if e != nil {
				return e
			}
			if len(existing) > 0 && score >= strong {
				old, e := checkedRecord(existing[0])
				if e != nil {
					return e
				}
				if obj(old["answer"])["verbatim"] != text || old["kind"] != "owner-decision" || !equalValue(old["level"], identity["level"]) || old["instance"] != identity["instance"] || (target != "" && old["supersedes"] != target) {
					return invalid("owner decision content id conflicts with stored record")
				}
				reason := ""
				if target != "" {
					reason, e = targetReason(ctx, w, target, identity, id)
					if e != nil {
						return e
					}
				}
				if reason != "" {
					receipt["review"] = true
					receipt["review_reason"] = reason
					reviewRecord = record
				} else {
					receipt["stored"] = true
					receipt["existing"] = true
					receipt["id"] = id
				}
				return nil
			}
			reason := ""
			if target != "" {
				reason, e = targetReason(ctx, w, target, identity, "")
				if e != nil {
					return e
				}
				if reason != "" {
					receipt["review_reason"] = reason
				}
			}
			if score < strong || reason != "" {
				receipt["review"] = true
				reviewRecord = record
				return nil
			}
			if target != "" {
				record["supersedes"] = target
				oldRows, e := readRows(ctx, w, "SELECT * FROM records WHERE id = ?", target)
				if e != nil {
					return e
				}
				old, e := checkedRecord(oldRows[0])
				if e != nil {
					return e
				}
				old["status_before_superseded"] = old["status"]
				old["status"] = "superseded"
				old["superseded_by"] = id
				if e = insertRecord(ctx, w, record); e != nil {
					return e
				}
				if e = updateRecord(ctx, w, old); e != nil {
					return e
				}
			} else if e = insertRecord(ctx, w, record); e != nil {
				return e
			}
			receipt["stored"] = true
			receipt["id"] = id
			return nil
		})
		if e != nil {
			return nil, e
		}
		if reviewRecord != nil {
			entry := copyObject(receipt)
			entry["record"] = reviewRecord
			if e = appendLog(o.review, entry); e != nil {
				return nil, e
			}
		}
	}
	receipt["event"] = "capture-outcome"
	if e = appendLog(o.captureLog, receipt); e != nil {
		return nil, e
	}
	return receipt, nil
}

var _ io.Writer = (*judgeBuffer)(nil)
