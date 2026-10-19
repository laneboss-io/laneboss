package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/policy"
	"laneboss.io/laneboss/internal/v2/templates"
)

type InitialRequest struct {
	Manifest api.BlobRef `json:"manifest"`
}
type InitialManifest struct {
	Schema         string                  `json:"schema"`
	Config         string                  `json:"config"`
	ID             api.ID                  `json:"id"`
	Generation     api.Generation          `json:"generation"`
	Runtime        api.BlobRef             `json:"runtime"`
	Launch         api.BlobRef             `json:"launch_enrollment"`
	Policy         api.BlobRef             `json:"policy"`
	Sources        api.BlobRef             `json:"sources"`
	SourceManifest api.BlobRef             `json:"source_manifest"`
	Profiles       api.BlobRef             `json:"profiles"`
	Task           api.BlobRef             `json:"task"`
	L5             api.RoleContext         `json:"l5"`
	L5Sources      api.RoleTemplateSources `json:"l5_sources"`
	Objects        []api.BlobRef           `json:"objects"`
}
type InitialReceipt struct {
	Schema       string         `json:"schema"`
	Config       string         `json:"config"`
	ID           api.ID         `json:"id"`
	Manifest     api.BlobRef    `json:"manifest"`
	Receipt      api.BlobRef    `json:"receipt"`
	OperationID  api.ID         `json:"operation_id"`
	EventID      api.ID         `json:"event_id"`
	CommittedSeq api.Sequence   `json:"committed_seq"`
	Generation   api.Generation `json:"generation"`
}
type InitialPublisher interface {
	PublishInitial(context.Context, InitialRequest) (InitialReceipt, error)
}
type initialBundle struct {
	ref           api.BlobRef
	raw           []byte
	manifest      InitialManifest
	objects       map[api.ID][]byte
	policy        api.EffectivePolicy
	sources       api.OrgSnapshot
	profiles      api.RootGrantManifest
	enrollment    InitialProfileEnrollment
	profileWrites []api.ObjectWrite
}

func initialRef(ref api.BlobRef) bool {
	return validID(ref.ID) && validDigest(ref.SHA256) && ref.Bytes >= 0 && (ref.Bytes > 0 || ref.Class == "artifact") && ref.Bytes <= api.MaxObjectBytes && (ref.Class == "manifest" || ref.Class == "task" || ref.Class == "artifact")
}

func validateInitial(ref api.BlobRef, raw []byte, objects map[api.ID][]byte, config string) (initialBundle, error) {
	return validateInitialObserved(nil, ref, raw, objects, config)
}

func validateInitialObserved(ctx context.Context, ref api.BlobRef, raw []byte, objects map[api.ID][]byte, config string) (initialBundle, error) {
	b := initialBundle{ref: ref, raw: raw, objects: objects}
	if !initialRef(ref) || ref.Class != "manifest" || int64(len(raw)) != ref.Bytes || digestBytes(raw) != ref.SHA256 {
		return b, failure(api.CodeIntegrity, "initial publication manifest pin differs")
	}
	if err := api.DecodeObject(raw, &b.manifest); err != nil {
		return b, err
	}
	m := b.manifest
	if m.Schema != "laneboss.initial.v2" || m.Config != config || !validConfig(config) || !validID(m.ID) || len(m.ID) > 64 || m.Generation != 1 || m.L5.Level != 5 || !validID(api.ID(m.L5.Role)) || m.L5.InstanceID != "" || len(m.Objects) == 0 || len(m.Objects) > 512 || ref.ID == initialReceiptID(config) {
		return b, failure(api.CodeInvalid, "initial publication identity or source set differs")
	}
	refs, err := initialStage(ctx, "object_hashes", func() (map[api.ID]api.BlobRef, error) {
		refs := map[api.ID]api.BlobRef{}
		var total int64
		for _, r := range m.Objects {
			data, exists := objects[r.ID]
			if !exists || !initialRef(r) || refs[r.ID].ID != "" || r.ID == ref.ID || r.ID == initialReceiptID(config) || int64(len(data)) != r.Bytes || digestBytes(data) != r.SHA256 {
				return nil, failure(api.CodeIntegrity, "initial publication object bytes differ")
			}
			refs[r.ID] = r
			total += r.Bytes
			if total > 64<<20 {
				return nil, failure(api.CodeBudget, "initial publication object bound exceeded")
			}
		}
		return refs, nil
	})
	if err != nil {
		return b, err
	}
	if len(objects) != len(refs) {
		return b, failure(api.CodeInvalid, "initial publication contains undeclared objects")
	}
	selectors := map[api.ID]bool{}
	for _, r := range []api.BlobRef{m.Runtime, m.Launch, m.Policy, m.Sources, m.SourceManifest, m.Profiles, m.Task} {
		if refs[r.ID] != r || selectors[r.ID] {
			return b, failure(api.CodeIntegrity, "initial document is absent or aliased in its exact object inventory")
		}
		selectors[r.ID] = true
	}
	if m.Runtime.Class != "manifest" || m.Launch.Class != "manifest" || m.Policy.Class != "manifest" || m.Sources.Class != "manifest" || m.SourceManifest.Class != "manifest" || m.Profiles.Class != "manifest" || m.Task.Class != "task" || !utf8.Valid(objects[m.Task.ID]) || strings.TrimSpace(string(objects[m.Task.ID])) == "" || strings.ContainsRune(string(objects[m.Task.ID]), 0) {
		return b, failure(api.CodeInvalid, "initial document classes or task text differ")
	}
	b.policy, err = initialStage(ctx, "policy_validate", func() (api.EffectivePolicy, error) {
		return policy.ValidateInitial(objects[m.Policy.ID])
	})
	if err != nil {
		return b, err
	}
	if err := api.DecodeObject(objects[m.Sources.ID], &b.sources); err != nil {
		return b, err
	}
	_, err = initialStage(ctx, "template_validate", func() (struct{}, error) {
		return struct{}{}, templates.ValidateInitialSources(config, b.sources, m.L5)
	})
	if err != nil {
		return b, err
	}
	if b.policy.Context != m.L5 {
		return b, failure(api.CodeInvalid, "initial policy context differs from the explicit L5 role")
	}
	if err := initialSourceManifest(b, refs); err != nil {
		return b, err
	}
	for _, f := range b.sources.Sources {
		if refs[f.Content.ID] != f.Content {
			return b, failure(api.CodeIntegrity, "initial source lacks its retained bytes")
		}
		data := objects[f.Content.ID]
		if !utf8.Valid(data) || strings.TrimSpace(string(data)) == "" || strings.ContainsRune(string(data), 0) {
			return b, failure(api.CodeInvalid, "initial org source is not nonempty UTF-8 text")
		}
	}
	for _, s := range b.policy.Sources {
		found := false
		for _, f := range b.sources.Sources {
			found = found || f.Source == s
		}
		if !found {
			return b, failure(api.CodeIntegrity, "initial policy provenance differs from the org source set")
		}
	}
	var runtime api.RuntimeManifest
	var launch api.LaunchEnrollment
	if err := api.DecodeObject(objects[m.Runtime.ID], &runtime); err != nil {
		return b, err
	}
	if err := api.DecodeObject(objects[m.Launch.ID], &launch); err != nil {
		return b, err
	}
	if err := api.ValidateLaunchEnrollment(launch, config, m.Runtime); err != nil {
		return b, err
	}
	if err := initialRuntime(runtime, refs); err != nil {
		return b, err
	}
	for _, r := range launch.Runtimes {
		if err := initialExecutable(runtime, r.Executable); err != nil {
			return b, err
		}
	}
	if launch.Supervisor != nil {
		if err := initialExecutable(runtime, *launch.Supervisor); err != nil {
			return b, err
		}
	}
	if err := initialExecutable(runtime, b.sources.Renderer); err != nil {
		return b, err
	}
	if refs[b.sources.OwnershipManifest.ID] != b.sources.OwnershipManifest {
		return b, failure(api.CodeIntegrity, "initial ownership manifest is not retained")
	}
	if err := manifest.Decode(objects[m.Profiles.ID], &b.profiles); err != nil {
		return b, err
	}
	if err := manifest.Root(b.profiles, time.Time{}); err != nil {
		return b, err
	}
	if len(b.profiles.Profiles) == 0 {
		return b, failure(api.CodeInvalid, "initial profiles require the explicit root grant manifest")
	}
	for _, p := range launch.Projects {
		if refs[p.Object.ID] != p.Object {
			return b, failure(api.CodeIntegrity, "initial project manifest is not retained")
		}
		if _, err := initialTree(objects[p.Object.ID], refs, objects); err != nil {
			return b, err
		}
	}
	for _, g := range b.profiles.Data {
		r := refs[g.SourceObjectID]
		if r.ID == "" || r.Class != "manifest" || r.SHA256 != g.SourceSHA256 || g.PublicationID != "" {
			return b, failure(api.CodeIntegrity, "initial data grant lacks its retained source")
		}
		if _, err := initialTree(objects[r.ID], refs, objects); err != nil {
			return b, err
		}
	}
	if err := initialClosure(b, runtime, launch, refs); err != nil {
		return b, err
	}
	return b, nil
}

func initialReceiptID(config string) api.ID { return api.ID("initial-receipt-" + config) }

func initialObject(ref api.BlobRef, raw []byte, config string, actor api.Actor) api.ObjectWrite {
	return api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: append([]byte{}, raw...), SHA256: ref.SHA256, ACL: api.ObjectACL{Config: config, Owner: actor, Audience: "human", Participants: []api.ID{}, Generation: 1}, Origin: "service", InputRefs: []api.BlobRef{}}
}

func initialPlan(b initialBundle, actor api.Actor, now api.Timestamp) (api.Transaction, error) {
	m := b.manifest
	intent := api.InternalIntent{ID: api.ID("initial-" + string(m.ID)), Kind: api.InternalOrgBootstrap, Config: m.Config, Actor: actor, RequestedBy: actor, CauseOperationID: api.ID("initial-op-" + string(m.ID)), CauseRequestID: m.ID}
	snapshot := b.sources
	snapshot.PublishedBy = m.ID
	snapshot.PublishedAt = now
	marker := api.InitialPublicationMarker{Schema: "laneboss.initial-marker.v2", Config: m.Config, ID: m.ID, Manifest: b.ref}
	raw, err := json.Marshal(marker)
	if err != nil {
		return api.Transaction{}, err
	}
	ref := api.BlobRef{ID: initialReceiptID(m.Config), Class: "manifest", SHA256: digestBytes(raw), Bytes: int64(len(raw))}
	objects := []api.ObjectWrite{initialObject(b.ref, b.raw, m.Config, actor), initialObject(ref, raw, m.Config, actor)}
	shared := map[api.ID]bool{b.sources.OwnershipManifest.ID: true}
	for _, source := range b.sources.Sources {
		shared[source.Content.ID] = true
	}
	for _, source := range b.sources.Derived {
		shared[source.Content.ID] = true
	}
	for _, r := range m.Objects {
		object := initialObject(r, b.objects[r.ID], m.Config, actor)
		if shared[r.ID] {
			object.ACL.Audience = "config"
		}
		objects = append(objects, object)
	}
	objects = append(objects, b.profileWrites...)
	event := api.Event{Schema: api.SchemaVersion, ID: api.ID("initial-event-" + string(m.ID)), Config: m.Config, Kind: "org.bootstrapped", Actor: actor, RequestedBy: actor, Origin: "service", StarterChain: []api.ID{}, Payload: raw}
	return api.Transaction{Scope: api.Scope{Config: m.Config, Actor: actor, Source: "service", PolicyGeneration: 1}, Internal: &intent,
		Compare: []api.Compare{{Kind: api.CompareOrg, ID: api.ID(m.Config), Generation: 0}},
		Writes:  api.StateWrites{OrgSnapshots: []api.OrgSnapshot{snapshot}, Policy: &b.policy, Objects: objects}, Events: []api.Event{event}}, nil
}

func initialMarkerMatches(raw []byte, b initialBundle) error {
	var m api.InitialPublicationMarker
	if err := api.DecodeObject(raw, &m); err != nil {
		return err
	}
	if m.Schema != "laneboss.initial-marker.v2" || m.Config != b.manifest.Config || m.ID != b.manifest.ID || m.Manifest != b.ref {
		return failure(api.CodeIdempotencyConflict, "initial publication already names different installed documents")
	}
	return nil
}

// VerifyInitialTransaction is the narrow store entry guard. The private
// native channel remains unforgeable by a public Scope or serialized intent.
func VerifyInitialTransaction(ctx context.Context, tx api.Transaction) error {
	channel, ok := ctx.Value(enrollmentChannelKey{}).(*enrollmentChannel)
	if !ok || channel == nil || channel.initial == nil {
		return failure(api.CodeForbidden, "initial publication requires the native administrator channel")
	}
	if err := CheckEnrollmentChannel(ctx, channel.endpoint); err != nil {
		return err
	}
	if !reflect.DeepEqual(tx, *channel.initial) {
		return failure(api.CodeForbidden, "initial publication changed its validated transaction")
	}
	raw, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	if digestBytes(raw) != channel.initialHash {
		return failure(api.CodeForbidden, "initial publication mutated its validated documents")
	}
	if len(tx.Compare) != 1 || tx.Compare[0] != (api.Compare{Kind: api.CompareOrg, ID: api.ID(tx.Scope.Config), Generation: 0}) {
		return failure(api.CodeForbidden, "initial publication lacks its empty-baseline compare")
	}
	return nil
}

func initialFailure(part string) error {
	return failure(api.CodeIntegrity, fmt.Sprintf("initial publication read-back differs: %s", part))
}

func initialExecutable(manifest api.RuntimeManifest, executable api.Executable) error {
	if !validID(executable.ID) || !validDigest(executable.SHA256) || executable.Version == "" {
		return failure(api.CodeInvalid, "initial executable pin is invalid")
	}
	for _, object := range manifest.Objects {
		if object.ID == executable.ID && object.Content.SHA256 == executable.SHA256 && object.Mode == 0555 {
			return nil
		}
	}
	return failure(api.CodeIntegrity, "initial executable is not in its protected runtime")
}
