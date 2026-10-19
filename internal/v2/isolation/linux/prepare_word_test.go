package linux

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPrepareWord(t *testing.T) {
	spec := fixtureSpec()
	helper := &helperTripwire{}
	s, err := New(Dependencies{Helper: helper, RuntimeManifest: spec.RuntimeManifest})
	if err != nil {
		t.Fatal(err)
	}
	spec.ID = ""
	word := ""
	ctx := api.WithHelperReasonObserver(context.Background(), func(cause error, check string) {
		if cause != nil && word == "" {
			word = check
		}
	})
	_, err = s.Prepare(ctx, spec)
	requireCode(t, err, api.CodeInvalid)
	if word != "linux_spec" || helper.calls != 0 || api.ErrorComponent(err) != "isolation_linux" {
		t.Fatal("actual spec refusal lost its owning check", word, helper.calls, api.ErrorComponent(err))
	}
}
