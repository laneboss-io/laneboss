package archive

import (
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestRetirementWireShapes(t *testing.T) {
	zero, exit := uint64(0), 7
	base := Retirement{JobID: "job", OperationID: "operation", EffectID: "effect", Target: api.LifeRef{LifeID: "life", Run: 1}, ObservedAt: "2026-10-16T00:00:00Z", Absent: true}
	for _, kind := range []string{"absent", "abort", "release", "boot"} {
		t.Run(kind, func(t *testing.T) {
			input := base
			if kind != "absent" {
				input.Absent = false
				input.Allocation = api.HelperLease{ID: "allocation", UID: 31001, GID: 31001, ContainmentID: "containment", EndpointGeneration: 1}
				observation := api.ProcessObservation{Handle: api.ProcessHandle{ID: "worker", Target: input.Target, ContainmentID: "containment", Generation: "boot:worker"}, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "cut", ObservedAt: input.ObservedAt}
				if kind == "boot" {
					input.Boot = &BootRetirement{PreviousBootID: "previous-boot", BootID: "current-boot", Process: observation.Handle, CgroupAbsent: true, Survivors: &zero, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: input.ObservedAt}
				} else if kind == "release" {
					input.Release = &api.ReleaseReceipt{ID: "release", LeaseID: "allocation", ContainmentID: "containment", Backend: "linux-bwrap-landlock", OperationID: input.OperationID, EffectID: input.EffectID, Quiescence: observation, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: input.ObservedAt}
				} else {
					observation.State, observation.ExitCode = "not_started", nil
					input.Abort = &api.AbortReceipt{ID: "abort", LeaseID: "allocation", Quiescence: observation, ObservedAt: input.ObservedAt}
				}
			}
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Retirement
			if err := api.DecodeObject(raw, &decoded); err != nil || !reflect.DeepEqual(decoded, input) {
				t.Fatal("native retirement union did not survive the real strict decoder", err)
			}
			malformed := append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"job_id":"substituted"}`)...)
			if err := api.DecodeObject(malformed, &decoded); err == nil {
				t.Fatal("retirement wire decoder accepted a duplicate original selector")
			}
		})
	}
}
