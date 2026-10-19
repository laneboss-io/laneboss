package policycase

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/job"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

// This is a real wire/tokenizer/cost check, not an installed native E2E claim.
func TestPolicyJudgeWire(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, "python3", "-I", "j_probe.py", "--root", root)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		input.Close()
		if err := command.Wait(); err != nil {
			t.Errorf("fixture probe failed: %v; %s", err, stderr.String())
		}
	})
	reader := bufio.NewReader(output)
	read := func(destination any) {
		t.Helper()
		raw, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatalf("producer lacks usable native judge enrollment: %v; %s", err, stderr.String())
		}
		if err := json.Unmarshal(raw, destination); err != nil {
			t.Fatalf("fixture protocol: %v", err)
		}
	}
	var enrollment struct {
		Judge    api.JudgeConfig `json:"judge"`
		Endpoint string          `json:"judge_endpoint"`
		MaxCost  int64           `json:"policy_max_cost_micros"`
		Worker   struct {
			Tokenizer string   `json:"tokenizer_path"`
			Args      []string `json:"tokenizer_args"`
			Reserve   int64    `json:"reserve_micros"`
			Safety    int      `json:"safety_tokens"`
			Price     string   `json:"price_file"`
			PriceSHA  string   `json:"price_sha256"`
		} `json:"judge_worker"`
	}
	read(&enrollment)
	price, err := os.ReadFile(enrollment.Worker.Price)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(price)
	if hex.EncodeToString(sum[:]) != enrollment.Worker.PriceSHA {
		t.Fatal("price pin changed")
	}
	var rates struct {
		Input  int64 `json:"input_micros_per_million"`
		Output int64 `json:"output_micros_per_million"`
	}
	if err := json.Unmarshal(price, &rates); err != nil {
		t.Fatal(err)
	}
	options := job.Options(job.Setup{Config: enrollment.Judge, Endpoint: enrollment.Endpoint,
		TokenizerPath: enrollment.Worker.Tokenizer, TokenizerArgs: enrollment.Worker.Args,
		SafetyTokens: enrollment.Worker.Safety, ReserveMicros: enrollment.Worker.Reserve,
		InputMicrosPerMillion: rates.Input, OutputMicrosPerMillion: rates.Output})
	retained := map[string][]byte{}
	options.Retain = func(_ context.Context, class string, raw []byte) (api.BlobRef, error) {
		id := fmt.Sprintf("object-%d", len(retained))
		retained[id] = bytes.Clone(raw)
		return api.BlobRef{ID: api.ID(id), Class: class, SHA256: wire.Digest(raw), Bytes: int64(len(raw))}, nil
	}
	adapter, err := wire.New(options)
	if err != nil {
		t.Fatal(err)
	}
	request := api.JudgeRequest{ID: "policy-wire-ask", Purpose: "blacklist", Config: enrollment.Judge,
		DeadlineMS: enrollment.Judge.CommandDeadlineMS, MaxCostMicros: enrollment.MaxCost,
		Rules: []api.JudgeRule{{ID: "fresh-cloud", Text: "Cloud machine creation must use the Laneboss box lifecycle.",
			SourceSHA256: wire.Digest([]byte("source")), CriteriaVersion: wire.CriteriaVersion}},
		Decisions: []api.DecisionCandidate{}, Task: []byte("wire fixture evidence"),
		Context: api.JudgeContext{Config: "policy-wire", Target: api.LifeRef{LifeID: "life-wire", Run: 1},
			Role: api.RoleContext{Level: 3, Role: "executor"}, LogicalTurnID: "turn-wire", GrantSetID: "grant-wire",
			GrantsSHA256: wire.Digest([]byte("grant")), PolicyGeneration: 2, CWD: "/work/main"}}
	evaluate := func(text string) api.JudgeReply {
		t.Helper()
		raw := []byte(text)
		request.Command = &api.CommandData{Tool: "shell", Command: raw, Argv: []string{}, DeclaredPaths: []string{}, CWD: "/work/main", RawSHA256: wire.Digest(raw)}
		reply, err := adapter.Evaluate(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	audit := func(reply api.JudgeReply) {
		t.Helper()
		fit, err := adapter.Fit(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		var raw []byte
		if reply.Raw != nil {
			raw = retained[string(reply.Raw.ID)]
		}
		if err := wire.AuditReply(reply, request, fit, raw); err != nil {
			t.Fatalf("fixture response cannot pass the real durable audit validator: %v", err)
		}
	}
	for index, sample := range []struct {
		rule string
		text string
		want float64
	}{
		{"Cloud machine creation must use the Laneboss box lifecycle.", "aws ec2 run-instances --dry-run", .90},
		{"Cloud machine creation must use the Laneboss box lifecycle.", "unfamiliar-reader --version", 0},
		{"Pull request creation must use the Laneboss review workflow.", "gh pr create --draft", .99},
		{"Restricted org publishing plugins require approved loading.", "use the restricted org publishing plugin", .99},
		{"Do not read the newly restricted public-readme.txt.", "cat public-readme.txt", .99},
		{"Do not read the newly restricted public-readme.txt.", "cat a-different-public-file.txt", 0},
		{"Do not publish executor output without independent review.", "cat public-readme.txt", 0},
		{"Cloud machine creation must use the Laneboss box lifecycle.", "tmux -L private-build new-session -d make", 0},
	} {
		request.Rules[0].ID = api.ID(fmt.Sprintf("unissued-rule-%d", index))
		request.Rules[0].Text = sample.rule
		reply := evaluate(sample.text)
		if reply.Status != "scored" || len(reply.Results) != 1 || reply.Results[0].Probability == nil ||
			*reply.Results[0].Probability != sample.want || reply.Request == nil || reply.Raw == nil || reply.CostMicros <= 0 {
			t.Fatalf("complete pinned fixture did not score actual input: %+v", reply)
		}
		if !bytes.Contains(retained[string(reply.Request.ID)], []byte(sample.text)) {
			t.Fatal("complete command was not retained")
		}
		audit(reply)
	}
	for index, stage := range []string{"timeout", "partial", "cost"} {
		raw, _ := json.Marshal(map[string]any{"stage": stage, "config": "policy-wire", "nonce": strings.Repeat("a", 32), "org_generation": index + 5})
		if _, err := fmt.Fprintln(input, string(raw)); err != nil {
			t.Fatal(err)
		}
		var control struct {
			Stage    string            `json:"stage"`
			Evidence []json.RawMessage `json:"evidence"`
		}
		read(&control)
		if control.Stage != stage || len(control.Evidence) == 0 {
			t.Fatal("controller did not retain its real transition")
		}
		reply := evaluate("read a public canary")
		if reply.Status == "scored" || len(reply.Results) != 1 || reply.Results[0].Probability != nil || reply.Request == nil {
			t.Fatalf("outage became a score: %+v", reply)
		}
		switch stage {
		case "timeout":
			if !strings.Contains(reply.UnavailableReason, "deadline") {
				t.Fatalf("timeout not reached: %+v", reply)
			}
		case "partial":
			if reply.Status != "partial" || reply.Raw == nil || !strings.Contains(reply.UnavailableReason, "partial") {
				t.Fatalf("partial not reached: %+v", reply)
			}
		case "cost":
			if reply.Raw == nil || reply.CostMicros <= enrollment.Worker.Reserve || reply.UnavailableReason != "actual judge cost exceeds its reserved budget" {
				t.Fatalf("real measured reservation overrun not reached: %+v", reply)
			}
		}
		audit(reply)
	}
	input.Close()
	// The probe closes both actual listeners and joins every serving thread.
	var closed map[string]any
	read(&closed)
	if closed["closed"] != true {
		t.Fatal("fixture collection absent")
	}
	if _, err := os.Stat(filepath.Join(root, "policy-http", "collection.json")); err != nil {
		t.Fatal(err)
	}
}
