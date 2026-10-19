package judge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/jobcatalog"
	"laneboss.io/laneboss/internal/typesafe"
)

// Job asks reuse the judge's bounded pipes, process cleanup and egress log.
// A configured shorter timeout is honored; a longer one cannot exceed this cap.
const JobTimeoutSeconds = 10
const JobQuestion = "laneboss.jobs"

// JobConfidenceFloor is an advisory routing threshold, not a calibrated claim.
const JobConfidenceFloor = 0.5

type JobVerdict struct {
	Verdict
	Command       string
	Confidence    float64
	Probabilities map[string]float64
}

func AskJobs(configuration, name, command string, catalog map[string]any) (JobVerdict, error) {
	return AskJobsContext(context.Background(), configuration, name, command, catalog)
}

func AskJobsContext(ctx context.Context, configuration, name, command string, catalog map[string]any) (JobVerdict, error) {
	// The entire job ask, including owner/log locks and cleanup, gets at most
	// ten seconds of the hook's remaining budget. Never renew its parent.
	ctx, cancel := context.WithTimeout(ctx, JobTimeoutSeconds*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return JobVerdict{Verdict: Verdict{Outcome: "timeout"}}, nil
	}
	o := options{config: configuration, configSet: true, judge: name, question: JobQuestion, questionSet: true}
	if lane := os.Getenv("LANEBOSS_LANE"); lanePattern.MatchString(lane) {
		o.lane, o.laneSet = lane, true
	}
	if !namePattern.MatchString(name) || hasCredential(name) {
		return JobVerdict{}, refused("job judge needs a valid configured name")
	}
	c, err := loadConfiguration(o)
	if err != nil {
		return JobVerdict{}, err
	}
	j, ok := c.judges[name]
	if !ok {
		return JobVerdict{}, refused("the job judge is not configured")
	}
	j.seconds = min(j.seconds, JobTimeoutSeconds)
	criteria, err := jobcatalog.Criteria(catalog)
	if err != nil {
		return JobVerdict{}, err
	}
	state := map[string]any{"shell_command": command}
	for key, value := range catalog {
		state[key] = value
	}
	state["shell_command"] = command
	questions := map[string]any{
		"owned": map[string]any{"type": "noul", "instructions": "Does `shell_command` perform a job listed in `laneboss_jobs` on a Laneboss-managed object identified by `managed_objects`?",
			"criteria": map[string]any{"true": "The command performs a catalog job on a recorded Laneboss lane, worktree, session, process, event store or dashboard.", "false": "The command performs ordinary unrelated work, or no recorded managed target supports the catalog match; resemblance to tmux, git, curl or kill alone is insufficient."}},
		"command": map[string]any{"type": "choice", "instructions": "Which command in `laneboss_jobs` handles the job that `shell_command` performs on a Laneboss-managed object in `managed_objects`? Answer none for ordinary unrelated shell work; similarity to a command is insufficient.", "criteria": criteria},
	}
	body := map[string]any{"laneboss_judge": 1, "question": JobQuestion, "kind": "laneboss-jobs",
		"state": state, "questions": questions}
	data := append(encodeJSON(body), '\n')
	if len(data) > 256*1024 {
		return JobVerdict{Verdict: Verdict{Outcome: "cut"}}, nil
	}
	if _, found := credentialField(body, ""); found {
		return JobVerdict{Verdict: Verdict{Outcome: "withheld"}}, nil
	}
	sum := sha256.Sum256(data)
	r := request{data: data, hash: hex.EncodeToString(sum[:]), withheld: []string{}, cut: []string{},
		decode: func(raw []byte) (answer, bool) { return readJobAnswer(raw, criteria) }}
	if faults.Get("jobs-batch-panic").Point != "" {
		if err := faults.Reach("jobs-batch-panic"); err != nil {
			panic(err)
		}
		panic("injected job batch panic")
	}
	result, detail, interrupted, err := askJudgeContext(ctx, c, o, j, r)
	if ctx.Err() != nil {
		return JobVerdict{Verdict: Verdict{Outcome: "timeout"}}, nil
	}
	if err != nil {
		return JobVerdict{}, err
	}
	v := JobVerdict{Verdict: Verdict{Outcome: result.Outcome, Detail: detail}, Command: result.command, Confidence: result.confidence, Probabilities: result.distribution}
	if interrupted {
		v.Outcome = "exit"
	}
	if result.Probability != nil {
		v.Probability = *result.Probability
	}
	if result.Model != nil {
		v.Model = *result.Model
	}
	return v, nil
}

func readJobAnswer(raw []byte, criteria map[string]string) (answer, bool) {
	var a answer
	options := map[string]any{}
	for key, value := range criteria {
		options[key] = value
	}
	questions := map[string]any{
		"owned":   map[string]any{"type": "noul", "instructions": "Does the command perform a catalog job on a managed object?"},
		"command": map[string]any{"type": "choice", "instructions": "Which catalog command applies?", "criteria": options},
	}
	root, err := typesafe.Response(raw, questions)
	if err != nil {
		return a, false
	}
	if _, found := credentialField(root, ""); found {
		return a, false
	}
	answers, ok := root["answers"].(map[string]any)
	if !ok {
		return a, false
	}
	owned, ownedOK := answers["owned"].(map[string]any)
	choice, choiceOK := answers["command"].(map[string]any)
	if !ownedOK || !choiceOK || owned["type"] != "noul" || choice["type"] != "choice" {
		return a, false
	}
	p, pOK := probability(owned["noul"])
	command, commandOK := choice["choice"].(string)
	confidence, confidenceOK := probability(choice["confidence"])
	_, known := criteria[command]
	if !pOK || !commandOK || !known || !confidenceOK {
		return a, false
	}
	model, modelOK := optionalIdentifier(root["model"])
	identifier, identifierOK := optionalIdentifier(root["request"])
	if !modelOK || !identifierOK {
		return a, false
	}
	distribution := map[string]float64{}
	for option, value := range tableValue(choice["probabilities"]) {
		p, ok := probability(value)
		if !ok {
			return a, false
		}
		distribution[option] = p
	}
	return answer{p: &p, model: model, request: identifier, command: command, confidence: confidence, distribution: distribution}, true
}

func JobTimeoutNotice() string {
	return fmt.Sprintf("judge timeout is capped at %d seconds", JobTimeoutSeconds)
}
