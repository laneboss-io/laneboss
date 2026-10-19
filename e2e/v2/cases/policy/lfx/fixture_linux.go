//go:build linux

// Package lfx supplies actual policy producer inputs to component
// tests. It never enrolls a human, authenticates a model or opens a native gate.
package lfx

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type Inputs struct {
	Approved    api.RootGrantManifest `json:"approved"`
	RootRequest api.RootGrantRequest  `json:"root_request"`
	Ceiling     api.GrantSet          `json:"ceiling"`
	Launches    []api.StartRequest    `json:"launches"`
	Documents   []struct {
		Ref  api.BlobRef `json:"ref"`
		Data []byte      `json:"data"`
	} `json:"documents"`
	Project        api.BlobRef `json:"project"`
	ProjectGrantID api.ID      `json:"project_grant_id"`
	Enrollment     api.BlobRef `json:"enrollment"`
	Runtime        api.BlobRef `json:"runtime"`

	OrgSnapshot api.OrgSnapshot     `json:"org_snapshot"`
	Policy      api.EffectivePolicy `json:"policy"`
}

func Load(t testing.TB, source string, options ...string) Inputs {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "actual-policy-inputs.json")
	probe := filepath.Join(source, "e2e", "v2", "cases", "policy", "l_probe.py")
	args := append([]string{"-I", probe, "--output", path}, options...)
	command := exec.CommandContext(ctx, "python3", args...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual policy boot/assembly/binding: %v\n%s", err, output)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var in Inputs
	if err := api.DecodeObject(raw, &in); err != nil {
		t.Fatal(err)
	}
	if err := manifest.Root(in.Approved, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := manifest.RootInput(in.RootRequest); err != nil {
		t.Fatal(err)
	}
	approved := api.RootGrantManifest{Schema: in.Approved.Schema, Resources: in.Ceiling.Resources,
		Data: append([]api.DataGrant{}, in.Ceiling.Data...), Secrets: in.Ceiling.Secrets,
		Profiles: append([]api.ProfileGrant{}, in.Ceiling.Profiles...), Network: in.Ceiling.Network, Channels: in.Ceiling.Channels}
	for i := range approved.Data {
		approved.Data[i].ID = ""
	}
	for i := range approved.Profiles {
		approved.Profiles[i].ID = ""
	}
	if !reflect.DeepEqual(approved, in.Approved) {
		t.Fatal("component identities replaced actual policy root scope")
	}
	in.Ceiling.SHA256, err = manifest.HashValue(in.Ceiling)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Set(in.Ceiling, time.Now()); err != nil {
		t.Fatal(err)
	}
	return in
}

// Reserve installs only primitive component publication/ticket identities.
// Actual policy, document bytes, grant scope and launch fields are preserved;
// reservation, the planning outbox and its claim come from the real writer.
func (in Inputs) Reserve(t testing.TB, driver api.Driver) *fx.Fixture {
	t.Helper()
	f := fx.New(t, in.OrgSnapshot.Config)
	f.Replace(t, "policy", api.ID(f.Deps.Config), in.Policy.Generation, in.Policy)
	var start api.StartRequest
	count := 0
	for _, candidate := range in.Launches {
		if candidate.Driver == driver {
			start = candidate
			count++
		}
	}
	if count != 1 || start.RootTicketID != "" || start.Budget != in.RootRequest.Budget {
		t.Fatal("actual driver proposal or root budget differs")
	}
	objects := []api.ObjectWrite{}
	for _, document := range in.Documents {
		if document.Ref.Bytes != int64(len(document.Data)) || document.Ref.SHA256 != fx.Digest(document.Data) {
			t.Fatal("actual assembler document lost its pinned bytes")
		}
		owner := f.Execution.Actor
		if document.Ref == start.Task {
			owner = f.Human.Actor
		}
		objects = append(objects, api.ObjectWrite{ObjectKey: document.Ref.ID, Class: document.Ref.Class,
			Bytes: document.Data, SHA256: document.Ref.SHA256, Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: owner, Audience: "owner", Generation: 1}})
	}
	snapshot := in.OrgSnapshot
	snapshot.PublishedBy, snapshot.PublishedAt = fx.ID(t), api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	cause := f.Intent(t, api.InternalOrgBootstrap)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause,
		Writes: api.StateWrites{Objects: objects, OrgSnapshots: []api.OrgSnapshot{snapshot}, Grants: []api.GrantSet{in.Ceiling}}}); err != nil {
		t.Fatal(err)
	}
	ticket, err := f.State.Ticket(context.Background(), f.Human, f.Start.RootTicketID)
	if err != nil {
		t.Fatal(err)
	}
	ticket.GrantSetID = in.Ceiling.ID
	f.Replace(t, "ticket", ticket.ID, 1, struct {
		RedeemedBy         api.ID
		PrincipalID        api.ID
		Config             string
		EndpointGeneration api.Generation
		Ticket             api.Ticket
	}{PrincipalID: ticket.PrincipalID, Config: ticket.Config, EndpointGeneration: ticket.EndpointGeneration, Ticket: ticket})
	f.Ceiling = in.Ceiling
	start.RootTicketID = ticket.ID
	f.Start = start
	f.Admit(t, "lane.start", start)
	f.Reserve(t)
	return f
}
