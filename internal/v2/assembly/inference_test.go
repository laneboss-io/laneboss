package assembly

import (
	"encoding/json"
	"fmt"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestInstalledInferenceEnrollment(t *testing.T) {
	for _, ceiling := range []int64{37, 0} {
		t.Run(fmt.Sprint(ceiling), func(t *testing.T) {
			base, err := json.Marshal(Installation{})
			if err != nil {
				t.Fatal(err)
			}
			var values map[string]any
			if err := json.Unmarshal(base, &values); err != nil {
				t.Fatal(err)
			}
			values["policy_max_cost_micros"] = ceiling
			data, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			var installed Installation
			err = api.DecodeObject(data, &installed)
			if err != nil {
				t.Fatal("approved inference enrollment cannot be decoded", err)
			}
			if installed.PolicyMaxCostMicros != ceiling {
				t.Fatal("installed inference ceiling was lost or replaced")
			}
		})
	}
}
