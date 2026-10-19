package service

import (
	"bytes"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestDeferralComponents(t *testing.T) {
	private := string(fixtureID(t))
	for _, kind := range []string{"PlanLaunch", "Worker"} {
		for _, code := range []api.ErrorCode{api.CodeContainmentUnknown, api.CodeDeadline, api.CodeUnavailable, api.CodeConflict} {
			cause := api.WithErrorComponent(&api.Error{Code: code, Owner: private, Message: private, Instead: private, OperationID: api.ID(private)}, "store_materialization")
			var journal bytes.Buffer
			attempt := effectAttempt{kind: kind}
			if err := attempt.writeTo(&journal, "deferred", "run_"+attempt.errorReason(cause)); err != nil {
				t.Fatal(err)
			}
			var entry map[string]string
			if json.Unmarshal(journal.Bytes(), &entry) != nil || entry["reason"] != "run_"+string(code)+"_store_materialization" || bytes.Contains(journal.Bytes(), []byte(private)) {
				t.Fatal("deferral lost its fixed refusing component or leaked a value", kind, code)
			}
		}
	}
}
