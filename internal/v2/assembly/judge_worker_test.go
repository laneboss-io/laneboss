package assembly

import (
	"context"
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestItem4JudgeMissingWorkerEnrollment(t *testing.T) {
	config := api.JudgeConfig{Provider: api.DefaultJudgeProvider, Model: api.DefaultJudgeModel,
		DeploymentSHA256: api.Digest(strings.Repeat("1", 64)), TokenizerSHA256: api.Digest(strings.Repeat("2", 64)),
		ContextTokens: 8192, MaxBytes: api.MaxJudgeBytes, MaxQuestions: 12, CommandDeadlineMS: 2000, GuidanceDeadlineMS: 5000, OutagePolicy: "critical-only"}
	provider := &installedJudge{provider: api.DefaultJudgeProvider, installation: Installation{Judge: config, JudgeEndpoint: "http://127.0.0.1:18081"}}
	_, err := provider.Fit(context.Background(), api.JudgeRequest{Config: config, DeadlineMS: 100})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite {
		t.Fatal("missing protected worker enrollment did not report its prerequisite", err)
	}
}
