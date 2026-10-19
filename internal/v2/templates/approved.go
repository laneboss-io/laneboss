package templates

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func newID() (api.ID, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", integrity("template operation entropy is unavailable")
	}
	return api.ID(hex.EncodeToString(value[:])), nil
}

func lifecycleRender(method api.Method) bool {
	return method == "lane.start" || method == "lane.adopt" || method == "lane.resume" || method == "lane.turn"
}

// A lifecycle call retains its original authenticated receipt requester. A method name
// alone is insufficient: the store must resolve that request's actual durable
// operation and the reserved life before any child prompt is retained.
func (s *Service) renderCause(ctx context.Context, scope api.Scope, lane *api.Lane) (api.ID, api.Actor, error) {
	if !lifecycleRender(scope.Request.Method) {
		if scope.Actor.Kind == "service" {
			return "", api.Actor{}, problem(api.CodeForbidden, "service rendering requires a reserved lifecycle cause",
				"Render through the original reserved lifecycle request; a service read label supplies no cause.")
		}
		return "", scope.Actor, nil
	}
	if lane == nil || scope.Request.Config != scope.Config || scope.Request.RequestID == "" ||
		scope.Request.IdempotencyKey == "" || !safeDigest.MatchString(string(scope.Request.RequestSHA256)) {
		return "", api.Actor{}, integrity("lifecycle render omits its prepared causal request")
	}
	digest, err := api.RequestDigest(scope.Request)
	if err != nil || digest != scope.Request.RequestSHA256 {
		return "", api.Actor{}, integrity("lifecycle render causal request differs from its exact intent")
	}
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err != nil {
		return "", api.Actor{}, err
	}
	// Config/key always bind the original reservation. A trusted service render
	// keeps the receipt's original lane/human requester rather than relabelling it.
	if receipt.Config != scope.Config || receipt.Key != key || receipt.Actor != scope.Actor && scope.Actor.Kind != "service" {
		return "", api.Actor{}, integrity("lifecycle render receipt differs from the authenticated request domain")
	}
	if scope.Actor.Kind == "service" &&
		(receipt.Actor.Kind != "lane" && receipt.Actor.Kind != "human" || !safeID.MatchString(string(receipt.Actor.ID)) ||
			receipt.Actor.Kind == "lane" && !safeID.MatchString(string(receipt.Actor.LifeID)) ||
			receipt.Actor.Kind == "human" && receipt.Actor.LifeID != "") {
		return "", api.Actor{}, problem(api.CodeForbidden, "service render receipt has no authentic lane or human requester",
			"Use the original lane/human lifecycle reservation and its actual requester.")
	}
	if !safeID.MatchString(string(receipt.Operation.ID)) ||
		receipt.Operation.LifeID != lane.LifeID ||
		(receipt.Operation.Status != "pending" && receipt.Operation.Status != "running") {
		return "", api.Actor{}, problem(api.CodeForbidden, "lifecycle render has no matching reserved life operation",
			"Reserve the authentic life under the authorized lifecycle operation before rendering its prompt.")
	}
	if err := renderReceiptReply(receipt); err != nil {
		return "", api.Actor{}, err
	}
	return receipt.Operation.ID, receipt.Actor, nil
}

// A queued public mutation can already have returned its pending Operation.
// That reply may accompany the active reservation, but cannot name another
// operation/life or claim that a completed/failed operation is still preparing.
func renderReceiptReply(receipt api.MutationReceipt) error {
	if receipt.Reply == nil {
		return nil
	}
	var operation api.Operation
	if receipt.Reply.Error != nil || DecodeJSON(receipt.Reply.Result, &operation) != nil ||
		operation.ID != receipt.Operation.ID || operation.Error != nil ||
		operation.LifeID != "" && operation.LifeID != receipt.Operation.LifeID ||
		(operation.Status != "pending" && operation.Status != "running") {
		return integrity("lifecycle render reply differs from its active reservation")
	}
	return nil
}

func promptObjectKey(scope api.Scope, input api.BriefingInput, snapshot api.OrgSnapshot,
	document Document, acl api.ObjectACL, refs []api.BlobRef, requester api.Actor, cause api.ID,
) (api.ID, error) {
	identity := struct {
		Namespace string             `json:"namespace"`
		Config    string             `json:"config"`
		Life      api.LifeRef        `json:"life"`
		LaneGen   api.Generation     `json:"lane_generation"`
		PolicyGen api.Generation     `json:"policy_generation"`
		Org       api.OrgSnapshotRef `json:"org"`
		Rendered  api.Digest         `json:"rendered_sha256"`
		ACL       api.ObjectACL      `json:"acl"`
		Inputs    []api.BlobRef      `json:"inputs"`
		Requester api.Actor          `json:"requester"`
		Operation api.ID             `json:"operation"`
	}{Namespace: "templates.prompt.v1", Config: scope.Config, PolicyGen: input.Policy.Generation,
		Org: snapshot.Ref, Rendered: document.Template.RenderedSHA256, ACL: acl, Inputs: refs,
		Requester: requester, Operation: cause}
	if input.Lane != nil {
		identity.Life = api.LifeRef{LifeID: input.Lane.LifeID, Run: input.Lane.Run}
		identity.LaneGen = input.Lane.Generation
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", integrity("prompt retention identity could not be encoded")
	}
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		return "", err
	}
	return api.ID(hash(canonical)), nil
}

func checkSnapshot(scope api.Scope, snapshot api.OrgSnapshot) error {
	ref := snapshot.Ref
	if snapshot.Config != scope.Config || ref.OrgID != api.ID(scope.Config) || !safeID.MatchString(string(ref.OrgID)) ||
		ref.Generation == 0 || ref.Generation > maxGeneration || !safeDigest.MatchString(string(ref.ManifestSHA256)) ||
		!safeID.MatchString(string(snapshot.Renderer.ID)) || !safeDigest.MatchString(string(snapshot.Renderer.SHA256)) ||
		snapshot.Renderer.Version == "" || snapshot.OwnershipManifest.Class != "manifest" || len(snapshot.Sources) == 0 {
		return integrity("approved org snapshot omits its configuration, generation, renderer or inventory")
	}
	// Derived is decided by fix 13's generation-gated rule below (api.ValidateOrgKinds): an explicit empty
	// Derived at generation 1, a nonempty one after; a blanket nonempty check refused the initial publication.
	if err := checkBlobRef(snapshot.OwnershipManifest); err != nil {
		return err
	}
	// The initial publication has an explicit empty Derived array; subsequent
	// generations require generated files. The shared contract also rejects nil.
	if api.ValidateOrgKinds(snapshot) != nil {
		return integrity("approved org snapshot has invalid semantic source or derived kinds")
	}
	refs := make([]api.SourceRef, 0, len(snapshot.Sources)+len(snapshot.Derived))
	for group, files := range [][]api.ResourceFile{snapshot.Sources, snapshot.Derived} {
		for _, file := range files {
			if !snapshotKind(file.Kind, group == 0) || file.Mode == 0 || file.Mode&^uint32(0777) != 0 ||
				file.RevisionGeneration == 0 || file.RevisionGeneration > ref.Generation ||
				file.Source.Generation != ref.Generation || file.Source.SHA256 != file.Content.SHA256 {
				return integrity("approved source inventory has invalid kind, mode, digest or revision generation")
			}
			if err := checkBlobRef(file.Content); err != nil {
				return err
			}
			refs = append(refs, file.Source)
		}
	}
	merged, err := mergeSources(nil, refs)
	if err != nil {
		return err
	}
	if len(merged) != len(refs) {
		return integrity("approved source inventory repeats a source identity or path")
	}
	return nil
}

func snapshotKind(kind string, source bool) bool {
	if !source {
		return kind == "file"
	}
	switch kind {
	case "prompt", "drivers", "policy", "source", "task":
		return true
	}
	return false
}

func (s *Service) sourceBytes(ctx context.Context, scope api.Scope, source api.TemplateSource, snapshot api.OrgSnapshot) ([]byte, error) {
	found := false
	for _, file := range snapshot.Sources {
		if file.Source == source.Source && file.Content == source.Content {
			found = true
		}
	}
	if !found {
		return nil, integrity("template source is outside the approved source inventory")
	}
	retained, err := s.deps.Store.Source(ctx, scope, source.Source)
	if err != nil {
		return nil, err
	}
	if retained.Source != source.Source || retained.Content != source.Content || source.Source.SHA256 != source.Content.SHA256 {
		return nil, integrity("approved source identity differs from its committed content")
	}
	if source.Content.Bytes > MaxSourceBytes {
		return nil, invalid("template source must be nonempty UTF-8 within 2 MiB")
	}
	return s.readBlob(ctx, scope, source.Content)
}

func (s *Service) resolveApproved(ctx context.Context, scope api.Scope, role api.RoleContext, provided api.TemplateSources) (*Resolved, api.OrgSnapshot, error) {
	if provided.Snapshot.OrgID != api.ID(scope.Config) {
		return nil, api.OrgSnapshot{}, problem(api.CodeConflict, "template snapshot belongs to another configuration",
			"Resolve the configuration's exact approved org generation.")
	}
	snapshot, err := s.deps.Store.OrgSnapshot(ctx, scope, api.OrgSnapshotRequest{OrgID: api.ID(scope.Config), Generation: provided.Snapshot.Generation})
	if err != nil {
		return nil, api.OrgSnapshot{}, err
	}
	if err := checkSnapshot(scope, snapshot); err != nil {
		return nil, api.OrgSnapshot{}, err
	}
	if provided.Snapshot != snapshot.Ref || provided.Context != role {
		return nil, api.OrgSnapshot{}, problem(api.CodeConflict, "template snapshot is stale or belongs to another role",
			"Resolve the current approved org generation and exact role.")
	}
	current, err := s.deps.Store.TemplateSources(ctx, scope, api.TemplateSourceRequest{
		OrgID: snapshot.Ref.OrgID, Generation: snapshot.Ref.Generation, Context: role,
	})
	if err != nil {
		return nil, api.OrgSnapshot{}, err
	}
	if !reflect.DeepEqual(current, provided) {
		return nil, api.OrgSnapshot{}, integrity("briefing sources differ from the approved role selection")
	}
	localBase := fmt.Sprintf(".laneboss/L%d/roles/%s", role.Level, role.Role)
	localFiles := 0
	for _, file := range snapshot.Sources {
		if file.Source.Path == localBase+".md" || file.Source.Path == localBase+".toml" {
			localFiles++
		}
	}
	switch provided.LocalStatus {
	case "absent":
		if provided.Local != nil || localFiles != 0 {
			return nil, api.OrgSnapshot{}, integrity("absent local template status contradicts the approved inventory")
		}
	case "present":
		if provided.Local == nil || localFiles != 2 {
			return nil, api.OrgSnapshot{}, invalid("local role source and driver source must be a complete pair")
		}
	default:
		return nil, api.OrgSnapshot{}, integrity("approved local template status is neither absent nor present")
	}
	layers := Layers{Generation: snapshot.Ref.Generation}
	inputs := []api.TemplateSource{provided.Org.Prompt, provided.Org.Drivers}
	if provided.Local != nil {
		inputs = append(inputs, provided.Local.Prompt, provided.Local.Drivers)
	}
	sources := make([]Source, 0, len(inputs))
	for _, input := range inputs {
		data, err := s.sourceBytes(ctx, scope, input, snapshot)
		if err != nil {
			return nil, api.OrgSnapshot{}, err
		}
		sources = append(sources, Source{Ref: input.Source, Bytes: data})
	}
	layers.Org, layers.OrgDrivers = sources[0], sources[1]
	if len(sources) == 4 {
		layers.Local, layers.Drivers = &sources[2], &sources[3]
	}
	resolved, err := Resolve(role, layers)
	return resolved, snapshot, err
}

func (s *Service) renderBriefing(ctx context.Context, scope api.Scope, requested api.RoleContext, input api.BriefingInput, preparation *renderPreparation) (api.Briefing, error) {
	role := input.Policy.Context
	if role.Level != requested.Level || role.Role != requested.Role ||
		(requested.InstanceID != "" && role.InstanceID != requested.InstanceID) ||
		input.Policy.Generation == 0 || input.Policy.Generation > maxGeneration ||
		!safeDigest.MatchString(string(input.Policy.SHA256)) ||
		(scope.PolicyGeneration != 0 && scope.PolicyGeneration != input.Policy.Generation) {
		return api.Briefing{}, problem(api.CodeConflict, "briefing policy is stale or belongs to another role",
			"Resolve the current policy and authentic life before printing a briefing.")
	}
	if err := checkReadStatus(input.Checks, input.Groups); err != nil {
		return api.Briefing{}, err
	}
	var causeID api.ID
	var requester api.Actor
	causeRequestID := scope.Request.RequestID
	if preparation != nil {
		causeID, requester, causeRequestID = preparation.reservation.OperationID, preparation.reservation.RequestedBy, preparation.reservation.RequestID
	} else {
		var err error
		causeID, requester, err = s.renderCause(ctx, scope, input.Lane)
		if err != nil {
			return api.Briefing{}, err
		}
	}
	resolved, snapshot, err := s.resolveApproved(ctx, scope, role, input.Sources)
	if err != nil {
		return api.Briefing{}, err
	}
	var document Document
	refs := []api.BlobRef{}
	var target api.LifeRef
	var turn api.ID
	var epoch api.Generation
	acl := api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "owner", Generation: 1}
	switch input.Mode {
	case "lane":
		if input.Lane == nil || input.Task == nil || input.GrantSet == nil ||
			(lifeBound(scope) && input.Lane.LifeID != scope.Actor.LifeID) {
			return api.Briefing{}, integrity("lane briefing omits its authentic task or grants")
		}
		data, err := s.readBlob(ctx, scope, *input.Task)
		if err != nil {
			return api.Briefing{}, err
		}
		document, err = Render(RenderInput{Config: scope.Config, Role: resolved, Lane: *input.Lane,
			Grants: *input.GrantSet, Policy: input.Policy, Task: *input.Task, TaskBytes: data,
			NewLaunch: scope.Request.Method == "lane.start" || scope.Request.Method == "lane.adopt" ||
				preparation != nil && (preparation.reservation.Mode == "start" || preparation.reservation.Mode == "adopt")})
		if err != nil {
			return api.Briefing{}, err
		}
		refs = append(refs, *input.Task)
		target = api.LifeRef{LifeID: input.Lane.LifeID, Run: input.Lane.Run}
		turn, epoch = input.Lane.LogicalTurnID, input.Lane.CancellationEpoch
		acl.LifeID, acl.Audience = input.Lane.LifeID, "life"
	case "overview":
		if scope.Actor.Kind != "human" || input.Lane != nil || input.Task != nil || input.GrantSet != nil {
			return api.Briefing{}, integrity("human overview contains an invented life, task or grant set")
		}
		document, err = renderOverview(scope.Config, resolved, input)
		if err != nil {
			return api.Briefing{}, err
		}
	default:
		return api.Briefing{}, integrity("unknown service briefing input mode")
	}
	// Every consumed policy source must resolve through the same approved source
	// inventory. Source IDs are never interpreted as object IDs or host paths.
	for _, ref := range document.Sources {
		var content *api.BlobRef
		for _, file := range snapshot.Sources {
			if file.Source == ref {
				value := file.Content
				content = &value
			}
		}
		if content == nil {
			return api.Briefing{}, integrity("briefing provenance is outside the approved source snapshot")
		}
		if _, err := s.sourceBytes(ctx, scope, api.TemplateSource{Source: ref, Content: *content}, snapshot); err != nil {
			return api.Briefing{}, err
		}
		refs = append(refs, *content)
	}
	objectID, err := promptObjectKey(scope, input, snapshot, document, acl, refs, requester, causeID)
	if err != nil {
		return api.Briefing{}, err
	}
	intentID, err := newID()
	if err != nil {
		return api.Briefing{}, err
	}
	actor := api.Actor{Kind: "service", ID: "lb-v2-templates"}
	if preparation != nil && scope.Actor.Kind == "service" {
		actor = scope.Actor
	}
	ref, err := s.deps.Store.RetainObject(ctx, scope, api.RetainObjectRequest{
		Intent: api.InternalIntent{ID: intentID, Kind: api.InternalObjectRetain, Config: scope.Config,
			Actor: actor, RequestedBy: requester,
			CauseRequestID: causeRequestID, CauseOperationID: causeID,
			Target: target, LogicalTurnID: turn, CancellationEpoch: epoch},
		Object: api.ObjectWrite{ObjectKey: objectID, Class: "prompt", Bytes: bytes.Clone(document.Markdown),
			SHA256: document.Template.RenderedSHA256, ACL: acl, Origin: "service", InputRefs: refs},
	})
	if err != nil {
		return api.Briefing{}, err
	}
	if err := checkBlobRef(ref); err != nil {
		return api.Briefing{}, err
	}
	if ref.Class != "prompt" || ref.Bytes != int64(len(document.Markdown)) || ref.SHA256 != hash(document.Markdown) {
		return api.Briefing{}, integrity("retained prompt receipt differs from the exact rendered bytes")
	}
	briefing := api.Briefing{Markdown: ref, Template: document.Template, Sources: document.Sources,
		PolicyGeneration: input.Policy.Generation, Checks: input.Checks, LaneGroups: input.Groups}
	for _, group := range []*[]api.ID{&briefing.LaneGroups.Running, &briefing.LaneGroups.Ended, &briefing.LaneGroups.Accepted,
		&briefing.LaneGroups.Lost, &briefing.LaneGroups.Idle, &briefing.LaneGroups.Others} {
		if *group == nil {
			*group = []api.ID{}
		}
	}
	if err := VerifyPrompt(role, briefing, document.Markdown); err != nil {
		return api.Briefing{}, err
	}
	return briefing, nil
}

func checkReadStatus(checks []api.Capability, groups api.LaneGroups) error {
	if len(checks) == 0 {
		return integrity("briefing input omits its read capability checks")
	}
	seenChecks := map[string]bool{}
	for _, check := range checks {
		if check.Name == "" || seenChecks[check.Name] {
			return integrity("briefing input has missing or repeated capability names")
		}
		seenChecks[check.Name] = true
		if !check.Available {
			return problem(api.CodePrerequisite, "briefing contains an unavailable capability",
				"Inspect the briefing checks and repair the prerequisite before launching.")
		}
	}
	seen := map[api.ID]bool{}
	for _, group := range [][]api.ID{groups.Running, groups.Ended, groups.Accepted, groups.Lost, groups.Idle, groups.Others} {
		for _, life := range group {
			if !safeID.MatchString(string(life)) || seen[life] {
				return integrity("briefing groups contain an invalid or repeated lane life")
			}
			seen[life] = true
		}
	}
	return nil
}

func renderOverview(config string, role *Resolved, input api.BriefingInput) (Document, error) {
	if err := checkRules(input.Policy.Rules); err != nil {
		return Document{}, err
	}
	var output bytes.Buffer
	fmt.Fprintf(&output, "# Laneboss overview\n\nLevel: L%d\nRole: %s\nConfiguration: %s\n", role.context.Level, role.context.Role, config)
	fmt.Fprintf(&output, "Template: %s\nTemplate generation: %d\nTemplate source SHA-256: %s\nPolicy generation: %d\n\n",
		role.selected.ID, role.generation, role.selected.SHA256, input.Policy.Generation)
	output.WriteString("This is a human read-only overview. No life, workspace, task, grants or agent launch is assigned.\n\n")
	output.Write(role.body)
	output.WriteString("\n\n## Primary agent drivers\n\n")
	if err := appendJSON(&output, role.drivers); err != nil {
		return Document{}, err
	}
	fmt.Fprintf(&output, "\n\n## Org blacklist\n\nRead `laneboss org blacklist list --config %s` before dispatch.\n\n", config)
	for _, rule := range input.Policy.Rules {
		fmt.Fprintf(&output, "- [%s] (%s) %s\n  Instead: %s\n", rule.ID, rule.Band, rule.Text, rule.Instead)
	}
	output.WriteString("\n## Lane groups\n\n")
	if err := appendJSON(&output, input.Groups); err != nil {
		return Document{}, err
	}
	policySources := append([]api.SourceRef(nil), input.Policy.Sources...)
	for _, rule := range input.Policy.Rules {
		policySources = append(policySources, rule.Source)
	}
	sources, err := mergeSources(role.sources, policySources)
	if err != nil {
		return Document{}, err
	}
	output.WriteString("## Retained source references\n\n")
	if err := appendJSON(&output, sources); err != nil {
		return Document{}, err
	}
	if output.Len() > api.MaxObjectBytes {
		return Document{}, invalid("rendered prompt exceeds the object limit")
	}
	return Document{Markdown: bytes.Clone(output.Bytes()), Sources: sources,
		Template: api.TemplateRef{ID: role.selected.ID, SourceSHA256: role.selected.SHA256,
			Generation: role.generation, RenderedSHA256: hash(output.Bytes())}}, nil
}
