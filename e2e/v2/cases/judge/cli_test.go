package judgecase

import (
	"bytes"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
)

func TestNativeCLIArguments(t *testing.T) {
	for _, sample := range []struct {
		binding string
		code    api.ErrorCode
		exit    int
	}{
		{"/runtime/laneboss-worker.json", api.CodePrerequisite, 69},
		{"/runtime/foreign.json", api.CodeInvalid, 2},
	} {
		var out, errout bytes.Buffer
		code := cli.Run([]string{"internal", "judge", "--config", "judge-case",
			"--binding", sample.binding, "--lease", "judge-lease"}, bytes.NewReader(nil), &out, &errout)
		var failure api.Error
		if code != sample.exit || out.Len() != 0 || json.Unmarshal(errout.Bytes(), &failure) != nil || failure.Code != sample.code {
			t.Fatalf("native CLI lost its fixed binding/lease handoff: exit=%d failure=%s", code, errout.String())
		}
	}
}
