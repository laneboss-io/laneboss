package admin

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestHelperDataSuccessJournal(t *testing.T) {
	for _, method := range []string{"data_open", "data_prepare", "data_gate"} {
		var journal bytes.Buffer
		trace := helperRequestTrace{method: method, check: "operation"}
		if err := trace.write(&journal, nil); err != nil {
			t.Fatal(err)
		}
		var entry map[string]string
		if json.Unmarshal(journal.Bytes(), &entry) != nil || entry["method"] != method || entry["code"] != "ok" || entry["reason"] != "operation" {
			t.Fatal("successful native data call disappeared from its fixed journal", method)
		}
	}
}
