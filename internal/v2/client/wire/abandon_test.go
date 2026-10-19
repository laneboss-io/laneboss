package wire

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestAbandonEmptyReview(t *testing.T) {
	input := api.MarkRequest{Target: api.LifeRef{LifeID: "abandon-life", Run: 2}, ExpectedGeneration: 3, State: "abandoned",
		Review: api.ReviewReceipt{Checks: []api.BlobRef{}, RefusalResolution: []api.ID{}}}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"valid", "accepted", "merged", "unknown", "missing", "null", "duplicate", "wrong-type", "partial-review", "target-id", "empty-id", "large-generation"} {
		t.Run(fault, func(t *testing.T) {
			data := append([]byte{}, raw...)
			switch fault {
			case "accepted", "merged":
				data = bytes.Replace(data, []byte(`"abandoned"`), []byte(`"`+fault+`"`), 1)
			case "unknown":
				data = append(data[:len(data)-1], []byte(`,"unknown":0}`)...)
			case "missing":
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(data, &fields); err != nil {
					t.Fatal(err)
				}
				delete(fields, "review")
				data, err = json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
			case "null":
				data = bytes.Replace(data, []byte(`"checks":[]`), []byte(`"checks":null`), 1)
			case "duplicate":
				data = append(data[:len(data)-1], []byte(`,"state":"abandoned"}`)...)
			case "wrong-type":
				data = bytes.Replace(data, []byte(`"expected_generation":3`), []byte(`"expected_generation":"3"`), 1)
			case "partial-review":
				data = bytes.Replace(data, []byte(`"coverage":""`), []byte(`"coverage":"invented"`), 1)
			case "target-id":
				data = bytes.Replace(data, []byte(`"abandon-life"`), []byte(`"invalid/life"`), 1)
			case "empty-id":
				data = bytes.Replace(data, []byte(`"abandon-life"`), []byte(`""`), 1)
			case "large-generation":
				data = bytes.Replace(data, []byte(`"expected_generation":3`), []byte(`"expected_generation":9007199254740992`), 1)
			}
			var actual api.MarkRequest
			err := Decode(data, &actual)
			if fault != "valid" {
				if err == nil {
					t.Fatal("acceptance: abandonment schema admitted malformed or non-abandon empty review")
				}
				return
			}
			var shared api.MarkRequest
			if err != nil || api.DecodeObject(data, &shared) != nil || !reflect.DeepEqual(actual, input) || !reflect.DeepEqual(shared, input) {
				t.Fatal("acceptance: exact empty abandonment review disagreed between strict readers", err)
			}
			request := makeRequest(t, "lane.mark", input)
			encoded, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRequest(encoded); err != nil {
				t.Fatal("acceptance: exact abandonment request failed its real wire envelope", err)
			}
		})
	}
}
