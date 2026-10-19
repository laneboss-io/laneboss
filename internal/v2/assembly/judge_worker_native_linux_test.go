//go:build linux && laneboss_root_canary && laneboss_gate_integration

package assembly

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

// Explicit synthetic-tokenizer subprocess for the protected execution canary.
// It consumes actual stdin bytes and is never a model/tokenizer calibration.
func init() {
	if len(os.Args) != 4 || os.Args[1] != "--item4-fit" {
		return
	}
	body, err := io.ReadAll(io.LimitReader(os.Stdin, api.MaxJudgeBytes+1))
	contextTokens, parseErr := strconv.Atoi(os.Args[3])
	if err != nil || parseErr != nil || len(body) == 0 || len(body) > api.MaxJudgeBytes || !json.Valid(body) {
		os.Exit(2)
	}
	fit := api.TokenFit{Proved: true, InputBytes: len(body), InputTokens: utf8.RuneCount(body), ContextTokens: contextTokens, TokenizerSHA256: api.Digest(os.Args[2])}
	if json.NewEncoder(os.Stdout).Encode(fit) != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestItem4JudgeProtectedTokenizer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("protected worker canary requires the authorized disposable Linux root test")
	}
	directory, err := os.MkdirTemp("/opt", "lb-v2-it4-judge-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	}()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	program, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	programPath := filepath.Join(directory, "tokenizer")
	if err := os.WriteFile(programPath, program, 0555); err != nil {
		t.Fatal(err)
	}
	config := api.JudgeConfig{Provider: api.DefaultJudgeProvider, Model: api.DefaultJudgeModel, DeploymentSHA256: wire.Digest([]byte("declared synthetic deployment")), TokenizerSHA256: wire.Digest([]byte("declared synthetic tokenizer")), ContextTokens: 8192,
		MaxBytes: api.MaxJudgeBytes, MaxQuestions: 12, CommandDeadlineMS: 2000, GuidanceDeadlineMS: 5000, OutagePolicy: "critical-only"}
	price, err := json.Marshal(judgePrice{Schema: "laneboss.judge-price.v1", Provider: config.Provider, Model: config.Model, InputMicrosPerMillion: 1000, OutputMicrosPerMillion: 2000})
	if err != nil {
		t.Fatal(err)
	}
	pricePath := filepath.Join(directory, "price.json")
	if err := os.WriteFile(pricePath, price, 0444); err != nil {
		t.Fatal(err)
	}
	worker := JudgeWorkerInstallation{TokenizerPath: programPath, TokenizerArgs: []string{"--item4-fit", string(config.TokenizerSHA256), strconv.Itoa(config.ContextTokens)}, TokenizerExecutableSHA256: wire.Digest(program),
		PriceFile: pricePath, PriceSHA256: wire.Digest(price), SafetyTokens: 32, ReserveMicros: 19}
	installed := Installation{Judge: config, JudgeEndpoint: "http://127.0.0.1:18081", JudgeWorker: &worker}
	provider := &installedJudge{provider: config.Provider, installation: installed}
	command := []byte("git status --short")
	request := api.JudgeRequest{ID: "measured-request", Purpose: "preview", Rules: []api.JudgeRule{{ID: "rule-one", Text: "Keep the measured result.", SourceSHA256: wire.Digest([]byte("source")), CriteriaVersion: wire.CriteriaVersion}}, Decisions: []api.DecisionCandidate{}, Task: []byte("Review the build tree."),
		Config: config, DeadlineMS: 1000, MaxCostMicros: 19, Context: api.JudgeContext{Config: "native-fixture", Target: api.LifeRef{LifeID: "life-one", Run: 1}, Role: api.RoleContext{Level: 3, Role: "executor"}, LogicalTurnID: "turn-one", GrantSetID: "grant-one", GrantsSHA256: wire.Digest([]byte("grants")), PolicyGeneration: 1, CWD: "/work/main"},
		Command: &api.CommandData{Tool: "shell", Command: command, Argv: []string{}, DeclaredPaths: []string{}, CWD: "/work/main", RawSHA256: wire.Digest(command)}}
	fit, err := provider.Fit(context.Background(), request)
	if err != nil || !fit.Proved || fit.InputBytes <= 0 || fit.InputTokens <= 0 {
		t.Fatal("protected actual tokenizer process did not consume the complete request", err)
	}
	options, err := installedJudgeOptions(judgeEnrollments(installed)[0])
	if err != nil {
		t.Fatal(err)
	}
	if cost, err := options.Cost(1001, 3); err != nil || cost != 2 {
		t.Fatal("pinned measured price did not round actual usage", err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	provider.installation.JudgeEndpoint = server.URL
	retained := map[api.ID][]byte{}
	_, _, err = provider.EvaluateLeased(context.Background(), api.JudgeExecution{Request: request, Acquired: true}, func(ctx context.Context, class string, body []byte) (api.BlobRef, error) {
		id := api.ID(wire.Digest(body))
		retained[id] = append([]byte{}, body...)
		return api.BlobRef{ID: id, Class: class, SHA256: wire.Digest(body), Bytes: int64(len(body))}, ctx.Err()
	})
	if err == nil || calls.Load() != 0 {
		t.Fatal("installed provider sent without its native peer-bound worker job")
	}
	worker.TokenizerExecutableSHA256 = api.Digest(strings.Repeat("a", 64))
	fit, err = provider.Fit(context.Background(), request)
	if err == nil && fit.Proved {
		t.Fatal("changed tokenizer artifact retained a proved fit")
	}
	worker.TokenizerExecutableSHA256 = wire.Digest(program)
	worker.PriceSHA256 = api.Digest(strings.Repeat("b", 64))
	if _, err := provider.Fit(context.Background(), request); err == nil {
		t.Fatal("changed approved price was accepted")
	}
	worker.PriceSHA256 = wire.Digest(price)
	provider.installation.JudgeWorker = nil
	if _, err := provider.Fit(context.Background(), request); err == nil {
		t.Fatal("missing worker enrollment produced fit")
	}
	provider.installation.JudgeWorker = &worker
	provider.installation.JudgeCredentialHandle = "synthetic-credential"
	worker.CredentialFile = filepath.Join(directory, "synthetic-credential")
	material := []byte("synthetic-" + string(wire.Digest(program)))
	if err := os.WriteFile(worker.CredentialFile, material, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := installedJudgeOptions(judgeEnrollments(provider.installation)[0]); err == nil {
		t.Fatal("world-readable judge credential enrollment was accepted")
	}
	if err := os.Chmod(worker.CredentialFile, 0640); err != nil {
		t.Fatal(err)
	}
	options, err = installedJudgeOptions(judgeEnrollments(provider.installation)[0])
	if err != nil || string(options.Credential.Bytes) != string(material) {
		t.Fatal("protected credential control did not retain the actual enrolled bytes", err)
	}
}
