//go:build linux

package testfx

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// ReadyUsage creates a Claudock ended-run writer fixture. Its launch/capture
// receipts are component projections, never native helper authentication.
func ReadyUsage(t testing.TB) *Fixture {
	t.Helper()
	f := New(t)
	f.Start.Driver, f.Ceiling.Profiles[0].Driver = api.DriverClaudock, api.DriverClaudock
	f.Ceiling.SHA256 = ""
	var err error
	f.Ceiling.SHA256, err = manifest.HashValue(f.Ceiling)
	if err != nil {
		t.Fatal(err)
	}
	f.Replace(t, "grants", f.Ceiling.ID, f.Ceiling.Generation, f.Ceiling)
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlanForIdentity(t, true, uint32(os.Geteuid())+1, uint32(os.Getegid())+1)
	f.Spec(t)
	f.Bind(t)
	f.Opened(t)
	f.Ended(t)
	return f
}

// UsageWindow exercises reserved-class ownership through actual writer-issued
// jobs, claims, identity commits, acknowledgements and exact retained TSV.
// The owned cat command measures the supplied input bytes and exit. Its peer
// and frame remain explicitly post-authentication consumer fixtures; this is
// not outside vendor authentication, a native worker or installed acceptance.
func UsageWindow(t testing.TB, f *Fixture, percent string) api.BlobRef {
	t.Helper()
	ctx := context.Background()
	selected := f.Plan.Inputs.Grants.Profiles[0]
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: f.Lane.LifeID, Run: f.Lane.Run})
	if err != nil {
		t.Fatal(err)
	}
	var ended api.Timestamp
	for _, event := range page.Events {
		if event.Kind == "lane.ended" {
			var end api.RunEndEvent
			if err := api.DecodeObject(event.Payload, &end); err != nil {
				t.Fatal(err)
			}
			ended = end.Observation.ObservedAt
		}
	}
	if ended == "" {
		t.Fatal("usage fixture has no committed causing end")
	}
	input := api.UsageCredentialInput{Schema: "laneboss.usage-input.v1", ProfileGeneration: 1, VendorProfile: string(selected.ProfileID),
		Source: api.SecretGrant{ID: ID(t), Name: "component-usage-login", SourceHandle: ID(t), Version: "v1", Delivery: "file", Target: "login.json", ExpiresAt: Expiry()},
		Request: api.UsageWindowRequest{Target: f.Reservation.Target, LaunchID: f.Reservation.LaunchID, OperationID: f.Reservation.OperationID, ProfileGrantID: selected.ID, ProfileID: selected.ProfileID, Provider: selected.Provider,
			Executable: f.Plan.Runner.Executable, RuntimeManifest: f.Plan.Inputs.Sources.Runtime.Manifest, AdapterVersion: f.Plan.Runner.AdapterVersion, RunEndedAt: ended}}
	job, err := f.State.PrepareUsageJob(ctx, f.Execution, input)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: job.Lease.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	allocation := api.HelperLease{ID: ID(t), UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), ContainmentID: ID(t), EndpointGeneration: 1}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", Protocol: api.Protocol, APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision, Config: f.Deps.Config, Class: api.EndpointWorker,
		InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: uint32(os.Geteuid()) + 1000, ServiceGID: uint32(os.Getegid()) + 1000, Socket: "/runtime/laneboss-worker.sock", Backend: "linux-bwrap-landlock",
		ArtifactSHA256: job.Runtime.Executable.SHA256, ServiceVersion: job.Runtime.Executable.Version, LaunchID: job.LaunchID, Target: &job.Lease.Target, WorkerLeaseID: job.Lease.ID}
	injection := api.Injection{Target: job.Lease.Target, Outcome: "prepared", SlotIDs: []api.ID{ID(t)}, GrantIDs: []api.ID{input.Source.ID}, SourceVersions: []string{input.Source.Version}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}}
	handoff, err := f.State.UsageHandoff(ctx, f.Execution, claim, allocation, endpoint, injection)
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(stat[strings.LastIndex(string(stat), ")")+2:]))
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(fields) < 20 {
		t.Fatal("cannot read owned component lifetime", err)
	}
	generation := strings.TrimSpace(string(boot)) + ":" + fields[19]
	prepared := api.PreparedLaunch{ID: ID(t), GateID: ID(t), Target: job.Lease.Target, ContainmentID: allocation.ContainmentID, EndpointGeneration: 1, SpecSHA256: handoff.SpecSHA256, ProcessGeneration: generation}
	binding, err := f.State.BindUsageWorker(ctx, f.Execution, claim, prepared)
	if err != nil {
		t.Fatal(err)
	}
	facts := api.PeerFacts{HostUID: allocation.UID, HostGID: allocation.GID, HostPID: os.Getpid(), ProcessGeneration: generation, ContainmentID: allocation.ContainmentID}
	principal, err := f.State.WorkerBinding(ctx, endpoint, facts)
	if err != nil {
		t.Fatal(err)
	}
	source := []byte("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\n" + input.VendorProfile + "\tcomponent-plan\tcurrent\t" + percent + "\t" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano) + "\n")
	command := exec.CommandContext(ctx, "/usr/bin/cat")
	command.Env = []string{}
	command.Stdin = bytes.NewReader(source)
	measured, err := command.Output()
	if err != nil || command.ProcessState == nil || !bytes.Equal(measured, source) {
		t.Fatal("component usage command lost its actual source bytes", err)
	}
	observed := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	output := struct {
		Raw        []byte        `json:"raw"`
		ExitCode   int           `json:"exit_code"`
		ObservedAt api.Timestamp `json:"observed_at"`
	}{measured, command.ProcessState.ExitCode(), observed}
	encoded, err := api.CanonicalJSON(JSON(t, output))
	if err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: f.Deps.Config, Actor: binding.Record.Actor, LaunchID: binding.Record.ID, EndpointGeneration: 1, PolicyGeneration: 1,
		Connection: &Connection{Identity: ID(t), Endpoint: endpoint, Verified: &Peer{FactsValue: facts}}, Frame: &Frame{Raw: []byte("post-authentication usage writer frame")}}
	receipt, err := f.State.WorkerResult(ctx, scope, api.WorkerResultSubmission{LeaseID: job.Lease.ID, ExpectedGeneration: principal.Lease.Generation, InputSHA256: job.Lease.Input.SHA256, Result: encoded})
	if err != nil {
		t.Fatal(err)
	}
	retain := func(class string, raw []byte, inputs []api.BlobRef) api.BlobRef {
		ref, err := f.State.RetainObject(ctx, f.Execution, api.RetainObjectRequest{Intent: job.Cause, Object: api.ObjectWrite{ObjectKey: ID(t), Class: class, Bytes: raw, SHA256: Digest(raw), Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: job.Actor, LifeID: job.Lease.Target.LifeID, Audience: "service", Generation: 1}, InputRefs: inputs}})
		if err != nil {
			t.Fatal("component usage retention failed", err)
		}
		return ref
	}
	raw := retain("usage_raw", measured, []api.BlobRef{job.Lease.Input, receipt.Result})
	reader := csv.NewReader(bytes.NewReader(measured))
	reader.Comma, reader.FieldsPerRecord = '\t', 5
	rows, err := reader.ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatal("component usage source is not its exact TSV", err)
	}
	used, err := strconv.ParseFloat(rows[1][3], 64)
	if err != nil {
		t.Fatal(err)
	}
	window := api.UsageWindowEvidence{Schema: "laneboss.usage-window.v2", ID: ID(t), Target: job.Lease.Target, LaunchID: input.Request.LaunchID, OperationID: job.Lease.OperationID,
		ProfileGrantID: selected.ID, ProfileID: selected.ProfileID, Provider: selected.Provider, AdapterVersion: input.Request.AdapterVersion, Executable: input.Request.Executable, RuntimeManifest: job.Lease.RuntimeManifest,
		WorkerLeaseID: job.Lease.ID, ProducerID: job.Actor.ID, ProducerGeneration: facts.ProcessGeneration, BootID: principal.BootID, ObservedAt: observed, Window: rows[1][2], UsedPercent: used, ResetsAt: api.Timestamp(rows[1][4]), ExitCode: output.ExitCode, Raw: raw, Row: 1}
	if err := api.ValidateUsageWindow(window, input.Request, principal, time.Now()); err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(window)
	if err == nil {
		encoded, err = api.CanonicalJSON(encoded)
	}
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.State.RetainObject(ctx, f.Execution, api.RetainObjectRequest{Intent: job.Cause, Object: api.ObjectWrite{ObjectKey: window.ID, Class: "usage_window", Bytes: encoded, SHA256: Digest(encoded), Origin: "service",
		ACL: api.ObjectACL{Config: f.Deps.Config, Owner: job.Actor, LifeID: job.Lease.Target.LifeID, Audience: "service", Generation: 1}, InputRefs: []api.BlobRef{raw, receipt.Result}}})
	if err != nil {
		t.Fatal("component window retention lost its real writer job", err)
	}
	return ref
}
