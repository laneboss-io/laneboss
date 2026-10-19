package start

import (
	"testing"

	"laneboss.io/laneboss/internal/testdata"
)

func observationFixture(t *testing.T) map[string]any {
	t.Helper()
	return testdata.ReplayEvent(t, parseJSON)
}

func TestObservationReplay(t *testing.T) {
	event := observationFixture(t)
	if err := lanePayload(str(event["kind"]), str(event["lane"]), object(event["payload"])); err != nil {
		t.Fatal(err)
	}
	row := emptyLane(str(event["lane"]))
	row["run"] = int64(1)
	if err := laneTransition(row, event); err != nil {
		t.Fatal(err)
	}
	applyRefusal(row, event)
	found := refusalState(row)
	if len(object(found["recorded"])) != 0 || len(object(found["suspected"])) != 1 || len(array(found["unreviewed"])) != 0 {
		t.Fatal("replay must preserve the observation without a refusal or acceptance hold")
	}
	if err := laneTransition(row, event); err == nil {
		t.Fatal("a repeated suspicion must still be rejected")
	}
}

func TestObservationContract(t *testing.T) {
	testdata.Contract(t, parseJSON, func(payload map[string]any) error {
		return lanePayload(testdata.EventKind, testdata.Lane, payload)
	})
}
