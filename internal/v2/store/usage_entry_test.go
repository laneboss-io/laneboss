//go:build linux

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/cli"
)

// Feed the actual writer-issued argv through the installed CLI parser. This
// checks the bootstrap route; help is not native authentication or job success.
func TestUsagePlanCLIEntry(t *testing.T) {
	f, input := usageReady(t)
	job, err := f.State.PrepareUsageJob(context.Background(), f.Execution, input)
	if err != nil {
		t.Fatal(err)
	}
	args := append(append([]string{}, job.Plan.Argv[1:]...), "--config", f.Deps.Config, "--help")
	var stdout, stderr bytes.Buffer
	code := cli.RunContext(context.Background(), args, strings.NewReader(""), &stdout, &stderr)
	var result struct {
		Command string `json:"command"`
		Method  string `json:"method"`
	}
	if code != 0 || json.Unmarshal(stdout.Bytes(), &result) != nil || result.Command != "internal worker" || result.Method != "" {
		t.Fatal("writer-issued usage plan does not reach the fixed installed worker CLI", code, stderr.String())
	}
}
