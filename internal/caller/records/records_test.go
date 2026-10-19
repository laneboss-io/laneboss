package records

import (
	"encoding/json"
	"testing"
)

func TestRecordedFieldsAndHistoricalNull(t *testing.T) {
	for _, p := range []map[string]any{{}, {"level": nil, "level_source": nil, "starter": nil}, {"level": json.Number("3"), "level_source": "protocol", "starter": "human"}, {"level": int64(4), "level_source": "supervisors", "starter": "lane:top-a"}, {"level": 6, "level_source": "instance", "starter": "supervisor:top"}} {
		if err := Validate(p); err != nil {
			t.Fatalf("valid recorded fields refused: %v", err)
		}
	}
	for _, p := range []map[string]any{{"level": 3}, {"level_source": "protocol"}, {"level": nil, "level_source": "protocol"}, {"level": 3.5, "level_source": "protocol"}, {"level": 2, "level_source": "protocol"}, {"level": 7, "level_source": "instance"}, {"level": "3", "level_source": "protocol"}, {"level": 3, "level_source": "inferred"}, {"starter": "human-spoof"}, {"starter": "lane:"}, {"starter": false}} {
		if err := Validate(p); err == nil {
			t.Fatalf("malformed report-line fields accepted: %#v", p)
		}
	}
	if !ValidSender("lane:worker-a") || !ValidSender("supervisor:mini-a") || !ValidSender("old-supervisor") || ValidSender("../other") {
		t.Fatal("canonical senders or historical sender validation is wrong")
	}
}
