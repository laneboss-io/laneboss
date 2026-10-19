package admin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/templates"
)

func initialTestContext(t *testing.T) (context.Context, *enrollmentChannel) {
	t.Helper()
	parent := context.Background()
	channel := &enrollmentChannel{endpoint: api.AdminEnrollmentEndpoint{Config: "admin-case"}}
	// Only a component capability. Native helper identity is covered by the
	// installed Linux case; these tests do not report such an identity.
	channel.verify = func() error {
		if channel.endpoint.Config != "admin-case" {
			return failure(api.CodeForbidden, "component channel binding changed")
		}
		return parent.Err()
	}
	return context.WithValue(parent, enrollmentChannelKey{}, channel), channel
}

func TestInitialOnce(t *testing.T) {
	b := initialFixture(t)
	ctx, ch := initialTestContext(t)
	s := &initialTestStore{path: filepath.Join(privateTestDir(t), "state.json")}
	clock := enrollmentClock{now: time.Now().UTC()}
	first, err := commitInitial(ctx, b, s, clock, ch)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	if s.calls != 1 || len(disk.Events) != 1 || len(disk.Objects) != len(b.objects)+2 || disk.Policy.SHA256 != b.policy.SHA256 || disk.Snapshot.Ref != b.sources.Ref || ch.initialReceipt == nil || *ch.initialReceipt != first {
		t.Fatal("acceptance: initial publication was skipped or lacks actual retained writes")
	}
	before, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := commitInitial(ctx, b, s, clock, ch)
	after, readErr := os.ReadFile(s.path)
	if err != nil || readErr != nil || second != first || s.calls != 1 || !reflect.DeepEqual(before, after) {
		t.Fatal("acceptance: initial publication was applied twice or resubmitted to the writer")
	}
	reopened := &initialTestStore{path: s.path}
	ctx2, ch2 := initialTestContext(t)
	third, err := commitInitial(ctx2, b, reopened, clock, ch2)
	if err != nil || third != first || reopened.calls != 0 {
		t.Fatal("acceptance: initial publication replay depended on process memory")
	}
}

func TestInitialSourceReadability(t *testing.T) {
	b := initialFixture(t)
	tx, err := initialPlan(b, api.Actor{Kind: "service", ID: "lb-v2-admin"}, api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano)))
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range b.sources.Sources {
		found := false
		for _, object := range tx.Writes.Objects {
			if object.ObjectKey == source.Content.ID {
				found = true
				if object.ACL.Audience != "config" {
					t.Fatal("installed lane cannot read its approved org source")
				}
			}
		}
		if !found {
			t.Fatal("initial source content was not published")
		}
	}
}

func TestInitialKinds(t *testing.T) {
	for _, name := range []string{"source", "derived"} {
		t.Run(name, func(t *testing.T) {
			b := initialFixture(t)
			if err := api.ValidateOrgKinds(b.sources); err != nil {
				t.Fatal("initial publication disagrees with the shared kind gate", err)
			}
			if err := templates.ValidateInitialSources(b.manifest.Config, b.sources, b.manifest.L5); err != nil {
				t.Fatal("initial publication disagrees with the template gate", err)
			}
			snapshot := b.sources
			snapshot.Sources = append([]api.ResourceFile(nil), b.sources.Sources...)
			if name == "source" {
				snapshot.Sources[2].Kind = "file"
			} else {
				file := snapshot.Sources[0]
				file.Kind = "file"
				snapshot.Derived = []api.ResourceFile{file}
			}
			replaceInitialDoc(t, &b, &b.manifest.Sources, snapshot)
			_, err := validateInitial(b.ref, b.raw, b.objects, b.manifest.Config)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
				t.Fatal("initial importer accepted an invalid source inventory", err)
			}
		})
	}
}

func TestInitialDelegate(t *testing.T) {
	b := initialFixture(t)
	if err := templates.ValidateInitialSources(b.manifest.Config, b.sources, b.manifest.L5); err != nil {
		t.Fatal("valid initial inventory was refused", err)
	}
	b.sources.Derived = nil
	err := templates.ValidateInitialSources(b.manifest.Config, b.sources, b.manifest.L5)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
		t.Fatal("initial validator bypassed the shared derived gate", err)
	}
}

func replaceInitialDoc(t *testing.T, b *initialBundle, ref *api.BlobRef, value any) {
	t.Helper()
	raw := initialEncode(t, value)
	ref.SHA256 = digestBytes(raw)
	ref.Bytes = int64(len(raw))
	b.objects[ref.ID] = raw
	for i, r := range b.manifest.Objects {
		if r.ID == ref.ID {
			b.manifest.Objects[i] = *ref
		}
	}
	b.raw = initialEncode(t, b.manifest)
	b.ref.SHA256 = digestBytes(b.raw)
	b.ref.Bytes = int64(len(b.raw))
}

func TestInitialDocs(t *testing.T) {
	for _, name := range []string{"policy", "sources", "profiles"} {
		t.Run(name, func(t *testing.T) {
			b := initialFixture(t)
			switch name {
			case "policy":
				p := b.policy
				p.Rules[0].Band = "allow"
				p.SHA256 = ""
				p.SHA256 = digestBytes(initialEncode(t, p))
				replaceInitialDoc(t, &b, &b.manifest.Policy, p)
			case "sources":
				s := b.sources
				s.PublishedBy = "caller-asserted"
				replaceInitialDoc(t, &b, &b.manifest.Sources, s)
			case "profiles":
				p := b.profiles
				p.Profiles[0].ID = "caller-issued"
				replaceInitialDoc(t, &b, &b.manifest.Profiles, p)
			}
			ctx, ch := initialTestContext(t)
			store := &initialTestStore{path: filepath.Join(privateTestDir(t), "state.json")}
			_, err := commitInitial(ctx, b, store, enrollmentClock{now: time.Now().UTC()}, ch)
			var typed *api.Error
			if err == nil || !errors.As(err, &typed) || typed.Code != api.CodeInvalid || store.calls != 0 {
				t.Fatal("acceptance: unvalidated initial document reached the publication writer")
			}
			if _, err := os.Stat(store.path); !os.IsNotExist(err) {
				t.Fatal("invalid initial document left a published state file")
			}
		})
	}
}

func TestInitialReceipt(t *testing.T) {
	b := initialFixture(t)
	ctx, ch := initialTestContext(t)
	clock := enrollmentClock{now: time.Now().UTC()}
	s := &initialTestStore{path: filepath.Join(privateTestDir(t), "state.json")}
	if _, err := commitInitial(ctx, b, s, clock, ch); err != nil {
		t.Fatal(err)
	}
	disk, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	disk.Events[0].OperationID = "foreign-operation"
	if err := os.WriteFile(s.path, initialEncode(t, disk), 0600); err != nil {
		t.Fatal(err)
	}
	ch.initialReceipt = nil
	if _, err := commitInitial(ctx, b, s, clock, ch); err == nil || ch.initialReceipt != nil || s.calls != 1 {
		t.Fatal("acceptance: initial publication acknowledged without its durable event binding")
	}
}

func TestInitialEventPage(t *testing.T) {
	b := initialFixture(t)
	ctx, ch := initialTestContext(t)
	clock := enrollmentClock{now: time.Now().UTC()}
	s := &initialTestStore{path: filepath.Join(privateTestDir(t), "state.json")}
	first, err := commitInitial(ctx, b, s, clock, ch)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	later := disk.Events[0]
	later.Seq++
	later.ID = "later-event"
	later.OperationID = "later-operation"
	disk.Events = append(disk.Events, later)
	if err := os.WriteFile(s.path, initialEncode(t, disk), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := commitInitial(ctx, b, s, clock, ch)
	if err != nil || second != first || s.calls != 1 {
		t.Fatalf("receipt included later events or submitted another publication: %v", err)
	}
}

func TestInitialSeq(t *testing.T) {
	b := initialFixture(t)
	ctx, ch := initialTestContext(t)
	clock := enrollmentClock{now: time.Now().UTC()}
	s := &initialTestStore{path: filepath.Join(privateTestDir(t), "state.json")}
	if _, err := commitInitial(ctx, b, s, clock, ch); err != nil {
		t.Fatal(err)
	}
	disk, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	disk.Events[0].Seq++
	if err := os.WriteFile(s.path, initialEncode(t, disk), 0600); err != nil {
		t.Fatal(err)
	}
	ch.initialReceipt = nil
	if _, err := commitInitial(ctx, b, s, clock, ch); err == nil || ch.initialReceipt != nil || s.calls != 1 {
		t.Fatal("acceptance: initial receipt accepted a foreign first event sequence")
	}
}

func TestInitialCAS(t *testing.T) {
	b := initialFixture(t)
	ctx, ch := initialTestContext(t)
	tx, err := initialPlan(b, api.Actor{Kind: "service", ID: "initial-admin-case"}, api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano)))
	if err != nil {
		t.Fatal(err)
	}
	tx.Compare[0].Generation = 1
	ch.initial = &tx
	raw, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	ch.initialHash = digestBytes(raw)
	if err := VerifyInitialTransaction(ctx, tx); err == nil {
		t.Fatal("acceptance: initial publication could replace a nonempty org baseline")
	}
}

func TestInitialPrivate(t *testing.T) {
	b := initialFixture(t)
	tx, err := initialPlan(b, api.Actor{Kind: "service", ID: "initial-admin-case"}, api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInitialTransaction(context.Background(), tx); err == nil {
		t.Fatal("initial store entry accepted a serialized service label")
	}
	if _, err := PublishInitial(context.Background(), InitialRequest{Manifest: b.ref}, nil, nil); err == nil {
		t.Fatal("initial import accepted a public caller")
	}
	ctx, ch := initialTestContext(t)
	ch.initial = &tx
	raw, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	ch.initialHash = digestBytes(raw)
	tx.Writes.Objects[0].Bytes[0] ^= 1
	if err := VerifyInitialTransaction(ctx, tx); err == nil {
		t.Fatal("initial store entry accepted mutated validated bytes")
	}
}
