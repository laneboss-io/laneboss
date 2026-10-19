package eventstore_test

import (
	"testing"

	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/testdata"
)

func decodeObservation(data []byte) (any, error) {
	return eventstore.Parse(data, "stored observation")
}

func TestObservationContract(t *testing.T) {
	testdata.Contract(t, decodeObservation, func(payload map[string]any) error {
		_, err := eventstore.Validate(testdata.Envelope(payload))
		return err
	})
}

func TestObservationStoredBytes(t *testing.T) {
	fixture := testdata.OpenStore(t)
	result, err := fixture.Store.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if result["ok"] != true {
		t.Fatal("the actual event store did not verify the stored observation")
	}
	row, err := fixture.Store.Lane(testdata.Lane)
	if err != nil {
		t.Fatal(err)
	}
	testdata.AssertState(t, row)
	duplicate := testdata.Envelope(testdata.Payload(t, decodeObservation))
	duplicate["id"] = "ev-observation-rescan"
	receipt, err := fixture.Store.Append(duplicate)
	if err != nil {
		t.Fatal(err)
	}
	if receipt["duplicate"] != true {
		t.Fatal("rescan must return the recorded observation's receipt")
	}
	events, err := fixture.Store.Events(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatal("rescan appended another observation")
	}
}
