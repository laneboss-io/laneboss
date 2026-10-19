package wire

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestMaterializationSchema(t *testing.T) {
	inputBytes := []byte("retained materialization input " + string(makeRequest(t, "health", api.HealthRequest{}).RequestID))
	resultBytes := []byte("retained worker result " + string(makeRequest(t, "health", api.HealthRequest{}).RequestID))
	input := api.BlobRef{ID: "sealed-input", Class: "materialize_input", Bytes: int64(len(inputBytes)), SHA256: digestOf(inputBytes)}
	result := api.BlobRef{ID: "sealed-result", Class: "worker_result", Bytes: int64(len(resultBytes)), SHA256: digestOf(resultBytes)}
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "materialize",
		Executable: api.Executable{ID: "worker-artifact", SHA256: digestOf(inputBytes), Version: "component-v1"},
		Argv:       []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", "job-lease"},
		Input:      input, GrantSetID: "job-grants", Budget: api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 4096, Processes: 1, DiskBytes: 4096}}
	grant := api.DataGrant{ID: "job-source", ParentGrantID: "source-grant", SourceObjectID: "source-object", SourceSHA256: digestOf(inputBytes),
		RelativePath: ".", Access: "ro", Delivery: "bind_ro", Destination: "/job/source", HistoryScope: "tree",
		ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}
	job := api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: "job-stage", LeaseID: "job-lease", Kind: "materialize",
		OperationID: "job-operation", EffectID: "job-effect", Input: input, Bytes: inputBytes}
	receipt := api.WorkerResultReceipt{LeaseID: job.LeaseID, StageID: job.StageID, Generation: 2, Result: result, CommittedSeq: 1}
	for _, item := range []struct {
		name  string
		value any
	}{
		{"input", input}, {"result", result}, {"plan", plan}, {"grant", grant}, {"bootstrap", job}, {"receipt", receipt},
	} {
		t.Run(item.name, func(t *testing.T) {
			raw, err := json.Marshal(item.value)
			if err != nil {
				t.Fatal(err)
			}
			decoded := reflect.New(reflect.TypeOf(item.value))
			if err := Decode(raw, decoded.Interface()); err != nil {
				t.Fatal("frozen materialization schema refused", err)
			}
			if !reflect.DeepEqual(decoded.Elem().Interface(), item.value) {
				t.Fatal("materialization schema changed retained values")
			}
		})
	}
	for _, class := range []string{input.Class, result.Class} {
		raw, err := json.Marshal(api.BlobBeginRequest{Class: class, Bytes: input.Bytes, SHA256: input.SHA256})
		if err != nil {
			t.Fatal(err)
		}
		var upload api.BlobBeginRequest
		if err := Decode(raw, &upload); err == nil {
			t.Fatal("public upload accepted a private worker class")
		}
	}
	request := api.DataGrantRequest{ParentGrantID: grant.ParentGrantID, RelativePath: grant.RelativePath, Access: grant.Access,
		Delivery: grant.Delivery, Destination: grant.Destination, ExpiresAt: grant.ExpiresAt}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var delegated api.DataGrantRequest
	if err := Decode(raw, &delegated); err == nil {
		t.Fatal("public grant request accepted private worker delivery")
	}
	plan.Kind = "unknown-worker"
	raw, err = json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var unknown api.WorkerPlan
	if err := Decode(raw, &unknown); err == nil {
		t.Fatal("worker schema accepted an unknown job kind")
	}
}
