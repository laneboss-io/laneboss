package dataworker

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/testjob"
)

type testDispatchControl struct {
	api.MaterializationControl
	call    testjob.Call
	request api.TestChildRequest
	grants  api.GrantSet
	count   int
	err     error
}

func (c *testDispatchControl) SubmitChildTest(_ context.Context, call testjob.Call, request api.TestChildRequest, grants api.GrantSet) (api.Operation, error) {
	c.call, c.request, c.grants = call, request, grants
	c.count++
	return api.Operation{}, c.err
}

func TestNativeChildDispatch(t *testing.T) {
	s, _, grants := workerFixture(t)
	stop := api.NotImplemented("component", "native execution belongs to the installed coordinator")
	control := &testDispatchControl{err: stop}
	s.deps.Controls = control
	ref := api.BlobRef{ID: "actual-candidate", Class: "manifest", Bytes: 2, SHA256: manifest.Hash([]byte("{}"))}
	request := api.TestChildRequest{Child: api.LifeRef{LifeID: grants.LifeID, Run: 2}, Candidate: ref, TestPlan: ref,
		Budget: api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 32 << 20, Processes: 4, DiskBytes: 1 << 20, Currency: "USD"}}
	call := testjob.Call{Scope: api.Scope{Config: "component", Actor: api.Actor{Kind: "human", ID: "actual-human"}},
		Guards: []api.TransactionGuard{{Proof: &api.ProofUse{Proof: api.ProofRef{ID: "actual-proof"}}}}}
	ctx := testjob.WithCall(context.Background(), call)
	_, err := s.TestChild(ctx, request, grants)
	if !errors.Is(err, stop) || control.count != 1 || !reflect.DeepEqual(control.call, call) || !reflect.DeepEqual(control.request, request) || !reflect.DeepEqual(control.grants, grants) {
		t.Fatal("TestChild did not hand the exact scoped request and child grants to its installed native coordinator", err)
	}
}
