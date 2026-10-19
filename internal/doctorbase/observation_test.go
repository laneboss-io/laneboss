package doctorbase

import (
	"testing"

	"laneboss.io/laneboss/internal/testdata"
)

func observationFixture(t *testing.T) map[string]any {
	t.Helper()
	return testdata.ReplayEvent(t, ParseJSON)
}

func TestObservationReplay(t *testing.T) {
	event := observationFixture(t)
	if err := validateLane(event); err != nil {
		t.Fatal(err)
	}
	row := emptyLane(String(event["lane"]))
	row["run"] = int64(1)
	if err := checkTransition(row, event); err != nil {
		t.Fatal(err)
	}
	applyRefusal(row, event)
	found := refusals(row)
	if len(Object(found["recorded"])) != 0 || len(Object(found["suspected"])) != 1 || len(Array(found["unreviewed"])) != 0 {
		t.Fatal("replay must preserve the observation without a refusal or acceptance hold")
	}
	if err := checkTransition(row, event); err == nil {
		t.Fatal("a repeated suspicion must still be rejected")
	}
}

func TestObservationContract(t *testing.T) {
	testdata.Contract(t, ParseJSON, func(payload map[string]any) error {
		return validateLane(testdata.Envelope(payload))
	})
}
