package dataworker

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

// Only the byte-backed bootstrap and native observation are component ports.
// Both the finding and its retained read-back come from the real review path.
func reviewDiffFindingResult(t *testing.T, paths []string, exit int) []byte {
	t.Helper()
	job, ports := reviewWorkerFixture(t, "valid")
	var input reviewjob.Input
	if err := api.DecodeObject(ports.input.Bytes, &input); err != nil {
		t.Fatal(err)
	}
	var base, current api.ObjectManifest
	if err := api.DecodeObject(ports.objects[input.Base.ID], &base); err != nil {
		t.Fatal(err)
	}
	if err := api.DecodeObject(ports.objects[input.Subject.Snapshot.ID], &current); err != nil {
		t.Fatal(err)
	}
	before, after := base.Entries[0], current.Entries[0]
	base.Entries, current.Entries = []api.ObjectEntry{}, []api.ObjectEntry{}
	for _, name := range paths {
		a, b := before, after
		a.Path, b.Path = name, "work/"+name
		base.Entries = append(base.Entries, a)
		current.Entries = append(current.Entries, b)
	}
	if len(paths) == 0 {
		a, b := before, before
		a.Path, b.Path = "unchanged.go", "work/unchanged.go"
		base.Entries, current.Entries = []api.ObjectEntry{a}, []api.ObjectEntry{b}
	}
	// Native project snapshots include root and parent directories. These
	// must not conceal a fake-only edit or manufacture a nonempty file diff.
	base.Entries = append(base.Entries, api.ObjectEntry{Path: ".", Kind: "directory", Mode: 0700})
	current.Entries = append(current.Entries, api.ObjectEntry{Path: "work", Kind: "directory", Mode: 0700},
		api.ObjectEntry{Path: "work/internal", Kind: "directory", Mode: 0700})
	put := func(id api.ID, class string, value any) api.BlobRef {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		ports.objects[id] = raw
		return api.BlobRef{ID: id, Class: class, Bytes: int64(len(raw)), SHA256: manifest.Hash(raw)}
	}
	input.Base = put(input.Base.ID, "manifest", base)
	input.Subject.Snapshot = put(input.Subject.Snapshot.ID, "manifest", current)
	input.Request.Diff = put(input.Request.Diff.ID, "diff", reviewTreeDiff(base, current, input.Base.SHA256, input.Subject.Snapshot.SHA256))
	for i := range input.Checks {
		fact := &input.Checks[i]
		var check reviewjob.CheckRecord
		if err := api.DecodeObject(ports.objects[fact.Receipt.ID], &check); err != nil {
			t.Fatal(err)
		}
		check.SnapshotSHA256, check.ExitCode = input.Subject.Snapshot.SHA256, exit
		fact.SnapshotSHA256, fact.ExitCode = check.SnapshotSHA256, check.ExitCode
		fact.Receipt = put(fact.Receipt.ID, "check", check)
		input.Request.Checks[i] = fact.Receipt
	}
	ref := put(ports.input.Input.ID, "manifest", input)
	job.Principal.Lease.Input = ref
	job.Principal.Claim.Record.Effect.Worker.Input = ref
	ports.input.Input, ports.input.Bytes = ref, ports.objects[ref.ID]

	state := &reviewResultState{job: job, ports: ports, lease: job.Principal.Lease, effect: job.Principal.Claim.Record}
	control := &reviewResultControl{state: state}
	service, _, _ := workerFixture(t)
	service.deps.Config, service.deps.Store, service.deps.Controls, service.deps.Clock = job.Scope.Config, state, control, job.Clock
	request, err := json.Marshal(input.Request)
	if err != nil {
		t.Fatal(err)
	}
	caller := api.Scope{Config: job.Scope.Config, Actor: job.Principal.Claim.Record.Effect.Context.RequestedBy,
		Request: api.Request{Config: job.Scope.Config, Method: "lane.review", Params: request}}
	prepared := api.ReviewVerifyRequest{Lease: job.Principal.Lease, Request: input.Request,
		ExpectedGeneration: input.Subject.Generation, EndEventID: input.Subject.EndEventID, EndSeq: input.Subject.EndSeq}
	evidence, err := service.VerifyReview(context.Background(), caller, prepared)
	if err != nil || control.calls != 1 || ports.submissions != 1 || state.output.SHA256 != manifest.Hash(ports.result) {
		t.Fatalf("real review did not retain and read back its result: %v", err)
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var retained, returned any
	if err := json.Unmarshal(ports.result, &retained); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &returned); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(retained, returned) {
		t.Fatal("reviewer's result differs from the retained worker output")
	}
	return raw
}

// Decode the public JSON shape so these tests also compile against the base
// revision: RED must be missing advisory output, never an undefined Go symbol.
func assertReviewDiffFinding(t *testing.T, raw []byte, want string, coverage string) {
	t.Helper()
	var result struct {
		Findings []struct {
			Kind    string `json:"kind"`
			Message string `json:"message"`
		} `json:"findings"`
		Untrusted *bool  `json:"untrusted"`
		Coverage  string `json:"coverage"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Coverage != coverage {
		t.Fatalf("advisory finding changed measured coverage: got %q, want %q", result.Coverage, coverage)
	}
	if want == "" {
		if len(result.Findings) != 0 || result.Untrusted != nil && *result.Untrusted {
			t.Fatalf("control diff was flagged: %s", raw)
		}
		return
	}
	if len(result.Findings) != 1 || result.Findings[0].Kind != want || result.Findings[0].Message == "" || result.Untrusted == nil || !*result.Untrusted {
		t.Fatalf("review did not expose %s as untrusted: %s", want, raw)
	}
}

func TestReviewDiffFindings(t *testing.T) {
	for _, test := range []struct {
		name     string
		paths    []string
		exit     int
		finding  string
		coverage string
	}{
		{"fakes-pass", []string{"internal/fakes/runner.go", "internal/fake_clock.go"}, 0, "fake_only_diff", api.CoverageComplete},
		{"fixtures-pass", []string{"fixtures/input.json", "internal/testdata/result.txt"}, 0, "fake_only_diff", api.CoverageComplete},
		{"mixed-pass", []string{"internal/check_test.go", "internal/check.go"}, 0, "", api.CoverageComplete},
		{"fakes-fail", []string{"internal/fakes/runner.go"}, 7, "", api.CoveragePartial},
		{"empty-pass", nil, 0, "empty_diff", api.CoverageComplete},
		{"docs-pass", []string{"docs/review.md", "README.md"}, 0, "", api.CoverageComplete},
		{"empty-fail", nil, 7, "", api.CoveragePartial},
		{"e2e-helper-pass", []string{"e2e/v2/box.py"}, 0, "fake_only_diff", api.CoverageComplete},
		{"e2e-case-pass", []string{"e2e/v2/cases/approval/case.py", "e2e/v2/cases/approval/run.sh", "e2e/v2/cases/approval/mutations.json"}, 0, "fake_only_diff", api.CoverageComplete},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := reviewDiffFindingResult(t, test.paths, test.exit)
			assertReviewDiffFinding(t, raw, test.finding, test.coverage)
		})
	}
}

func TestReviewTestOnlyPathPatterns(t *testing.T) {
	// Each production classifier rule has a positive and a near-miss control.
	// Exercise them through the verifier, including actual frozen tree reads.
	for _, test := range []struct{ pattern, positive, negative string }{
		{"*_test.go", "internal/check_test.go", "internal/check_test.go.bak"},
		{"testdata/", "internal/testdata/input.json", "internal/mytestdata/input.json"},
		{"fixtures/", "fixtures/input.json", "fixture/input.json"},
		{"fakes/", "internal/fakes/clock.go", "internal/fakeservice/clock.go"},
		{"fake_*.go", "internal/fake_clock.go", "internal/fake_clock.py"},
		{"*_fake.go", "internal/clock_fake.go", "internal/clock_fake.go.txt"},
		{"mocks/", "internal/mocks/clock.go", "internal/mockservice/clock.go"},
		{"mock_*.go", "internal/mock_clock.go", "internal/mock_clock.go.txt"},
		{"tests/", "pkg/tests/check.py", "pkg/contest/check.py"},
		{"*_test.py", "pkg/check_test.py", "pkg/check_test.pyc"},
		{"test_*.py", "pkg/test_check.py", "pkg/test_check.pyc"},
		{"*.spec.*", "web/check.spec.ts", "web/check.specification.ts"},
		{"*.test.*", "web/check.test.jsx", "web/check.testing.jsx"},
		{"e2e/", "e2e/v2/cases/approval/case.py", "internal/route_e2e/router.go"},
		{"e2e-rows/", "e2e-rows/sandbox_standin.py", "internal/e2e-rows-cache/cache.go"},
		{"testfixture/", "internal/v2/store/testfixture/run.go", "internal/v2/store/testfixtures/run.go"},
		{"testenv/", "internal/testenv/env.go", "internal/testenvironment/env.go"},
	} {
		t.Run(test.pattern, func(t *testing.T) {
			assertReviewDiffFinding(t, reviewDiffFindingResult(t, []string{test.positive}, 0), "fake_only_diff", api.CoverageComplete)
			assertReviewDiffFinding(t, reviewDiffFindingResult(t, []string{test.negative}, 0), "", api.CoverageComplete)
		})
	}
}
