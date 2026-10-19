package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/credentialtext"
	"laneboss.io/laneboss/internal/settings"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/templates"
)

const CanonicalPath = ".laneboss/policy.json"

var policyPath = regexp.MustCompile(`^\.laneboss/L([3-6])/policy/([A-Za-z0-9_-]+)\.json$`)
var policyRoot = regexp.MustCompile(`^\.laneboss/L[^/]+/policy/`)
var catalogPath = regexp.MustCompile(`^\.laneboss/L([3-6])/roles/([^/]+)\.(md|toml)$`)
var catalogRoot = regexp.MustCompile(`^\.laneboss/L[^/]+/roles/`)

// CanonicalDocument is approved source data, not an RPC. Defining scope comes
// from its retained inventory path, never from a field supplied by a client.
// Only the org baseline defines judge/guidance; role documents add rules and
// skips and supply settings for their own pair. Arrays are explicit, even empty.
type CanonicalDocument struct {
	Schema                  string             `json:"schema"`
	Thresholds              api.Thresholds     `json:"thresholds"`
	Rules                   []api.Rule         `json:"rules"`
	Skip                    []api.SkipEntry    `json:"skip"`
	Settings                []api.SettingValue `json:"settings"`
	Judge                   *api.JudgeConfig   `json:"judge,omitempty"`
	GuidanceHalfLifeSeconds *int64             `json:"guidance_half_life_seconds,omitempty"`
	GuidanceMinRelevance    *float64           `json:"guidance_min_relevance,omitempty"`
	ProfileExclusions       *[]api.ID          `json:"profile_exclusions,omitempty"`
}

type CanonicalView struct {
	Policy    api.EffectivePolicy
	Settings  []api.SettingValue
	Names     []string
	Resources []api.Resource
}

// CanonicalReader is an in-process source capability. A writer may provide
// its already authenticated transaction view without recursively locking or
// opening a second database snapshot.
type CanonicalReader interface {
	Source(context.Context, api.Scope, api.SourceRef) (api.RetainedSource, error)
	Blob(context.Context, api.Scope, api.BlobReadRequest) (api.BlobChunk, error)
}

type canonicalLayer struct {
	layer    Layer
	settings []api.SettingValue
	document CanonicalDocument
}

func CanonicalMissing() error {
	return &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-policy",
		Message: "approved canonical configuration source is absent",
		Instead: "Have the authorized administrator or L6 publish the complete canonical source inventory through its ordinary approval path."}
}

// HasCanonical selects the explicit format. It never infers source layers
// from a flattened policy or treats an unreadable source as absent.
func HasCanonical(org api.OrgSnapshot) bool {
	for _, file := range org.Sources {
		if CanonicalSourcePath(file.Source.Path) {
			return true
		}
	}
	return false
}

func CanonicalSourcePath(name string) bool {
	return name == CanonicalPath || policyRoot.MatchString(name)
}

// ReadCanonical consumes one authenticated immutable org view. It validates
// every policy layer, including unselected roles, then uses Resolve for both
// the retained default and requested role. The default digest is a fence
// against changing sources without advancing the approved policy projection.
func ReadCanonical(ctx context.Context, store CanonicalReader, scope api.Scope, approved api.EffectivePolicy, org api.OrgSnapshot, role api.RoleContext) (CanonicalView, error) {
	return readCanonical(ctx, store, scope, approved, org, role, true)
}

// CompileCanonical is the D6/installer compiler for exact already-approved
// source bytes. The caller supplies the target policy generation; there is no
// previous digest for a changed generation to match. Public reads use the
// ordinary retained-digest check in ReadCanonical.
func CompileCanonical(ctx context.Context, store CanonicalReader, scope api.Scope, target api.EffectivePolicy, org api.OrgSnapshot) (CanonicalView, error) {
	return readCanonical(ctx, store, scope, target, org, target.Context, false)
}

func readCanonical(ctx context.Context, store CanonicalReader, scope api.Scope, approved api.EffectivePolicy, org api.OrgSnapshot, role api.RoleContext, retained bool) (CanonicalView, error) {
	var empty CanonicalView
	if err := api.ValidateOrgSnapshotSelection(scope, api.OrgSnapshotRequest{OrgID: api.ID(scope.Config), Generation: org.Ref.Generation}, org); err != nil {
		return empty, err
	}
	if approved.Generation == 0 || approved.Generation != scope.PolicyGeneration {
		return empty, conflict("canonical policy generation changed")
	}
	if !validRole(role) || role.InstanceID != "" && role.InstanceID != approved.Context.InstanceID && (scope.Actor.Kind != "lane" || role.InstanceID != scope.Actor.ID) {
		return empty, forbiddenTarget()
	}
	if !HasCanonical(org) {
		return empty, CanonicalMissing()
	}
	ordered := append([]api.ResourceFile{}, org.Sources...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Source.Path < ordered[j].Source.Path })
	layers := []canonicalLayer{}
	roles := map[string]bool{}
	seenIDs, seenPaths := map[api.ID]bool{}, map[string]bool{}
	resources := []api.Resource{}
	catalog := map[string][]byte{}
	for _, file := range ordered {
		ref := file.Source
		if templates.ValidateSourceRef(ref) != nil || ref.Generation != org.Ref.Generation || file.RevisionGeneration == 0 || file.RevisionGeneration > ref.Generation || file.Content.SHA256 != ref.SHA256 || seenIDs[ref.ID] || seenPaths[ref.Path] {
			return empty, integrity("canonical source inventory is invalid or duplicated")
		}
		seenIDs[ref.ID], seenPaths[ref.Path] = true, true
		retained, err := store.Source(ctx, scope, ref)
		if err != nil {
			return empty, err
		}
		if retained.Source != ref || retained.Content != file.Content {
			return empty, integrity("canonical source differs from its retained content")
		}
		if match := catalogPath.FindStringSubmatch(ref.Path); match != nil {
			roles["L"+match[1]+"/"+match[2]] = true
		}
		kind := ""
		if strings.HasPrefix(ref.Path, "plugins/") {
			kind = "plugin"
		}
		if strings.HasPrefix(ref.Path, "channels/") {
			kind = "channel"
		}
		if kind != "" {
			resources = append(resources, api.Resource{ID: ref.ID, Kind: kind, Path: ref.Path,
				Version: strconv.FormatUint(uint64(file.RevisionGeneration), 10), SHA256: ref.SHA256,
				Source: file.Content, Declared: true, ObservedAt: org.PublishedAt})
		}
		match := policyPath.FindStringSubmatch(ref.Path)
		isPolicy := ref.Path == CanonicalPath || match != nil
		if !isPolicy && policyRoot.MatchString(ref.Path) {
			return empty, invalid("canonical role policy path is malformed")
		}
		templateKind := ""
		switch ref.Path {
		case templates.OrgTemplatePath:
			templateKind = "prompt"
		case templates.OrgDriversPath:
			templateKind = "drivers"
		case templates.WorkflowPath:
			templateKind = "policy"
		default:
			if catalogRoot.MatchString(ref.Path) {
				templateKind = "drivers"
				if strings.HasSuffix(ref.Path, ".md") {
					templateKind = "prompt"
				}
			}
		}
		if !isPolicy && templateKind == "" {
			continue
		}
		if isPolicy && file.Kind != "policy" || templateKind != "" && file.Kind != templateKind || file.Content.Bytes < 1 || file.Content.Bytes > templates.MaxSourceBytes {
			return empty, invalid("canonical input requires bounded source bytes with its actual semantic kind")
		}
		body, err := templates.ReadVerifiedBlob(ctx, file.Content, func(ctx context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
			return store.Blob(ctx, scope, request)
		})
		if err != nil {
			return empty, err
		}
		if templateKind != "" {
			catalog[ref.Path] = body
		}
		if !isPolicy {
			continue
		}
		var doc CanonicalDocument
		if err := api.DecodeObject(body, &doc); err != nil {
			return empty, err
		}
		if doc.Schema != "laneboss.policy-source.v2" || doc.Rules == nil || doc.Skip == nil || doc.Settings == nil {
			return empty, invalid("canonical policy source schema or arrays are incomplete")
		}
		entry := canonicalLayer{layer: Layer{Source: ref, Thresholds: doc.Thresholds, Rules: doc.Rules, Skip: doc.Skip}, document: doc}
		if match != nil {
			level, err := strconv.Atoi(match[1])
			if err != nil {
				return empty, invalid("canonical role level is invalid")
			}
			pair := api.RoleContext{Level: level, Role: match[2]}
			entry.layer.DefinedAt = &pair
			roles[fmt.Sprintf("L%d/%s", pair.Level, pair.Role)] = true
			if doc.Judge != nil || doc.GuidanceHalfLifeSeconds != nil || doc.GuidanceMinRelevance != nil || doc.ProfileExclusions != nil {
				return empty, invalid("role policy cannot redefine org judge or guidance settings")
			}
		}
		entry.settings, err = canonicalSettings(doc.Settings, ref)
		if err != nil {
			return empty, err
		}
		layers = append(layers, entry)
	}
	if err := templates.ValidateCatalog(catalog); err != nil {
		return empty, err
	}
	var baseline *canonicalLayer
	for i := range layers {
		if layers[i].layer.DefinedAt == nil {
			baseline = &layers[i]
		}
	}
	if baseline == nil {
		return empty, CanonicalMissing()
	}
	doc := baseline.document
	if doc.Judge == nil || doc.GuidanceHalfLifeSeconds == nil || doc.GuidanceMinRelevance == nil || doc.ProfileExclusions == nil || !finiteProbability(*doc.GuidanceMinRelevance) {
		return empty, invalid("canonical baseline omits approved judge or guidance settings")
	}
	resolve := func(selected api.RoleContext) (api.EffectivePolicy, error) {
		inputs := make([]Layer, len(layers))
		for i := range layers {
			inputs[i] = layers[i].layer
		}
		p, err := Resolve(approved.Generation, selected, inputs, *doc.Judge, *doc.GuidanceHalfLifeSeconds)
		if err != nil {
			return p, err
		}
		p.GuidanceMinRelevance, p.ProfileExclusions = *doc.GuidanceMinRelevance, append([]api.ID{}, (*doc.ProfileExclusions)...)
		p.AllowCaptureRefusal, p.CaptureRefusalApprovalID = approved.AllowCaptureRefusal, approved.CaptureRefusalApprovalID
		if err := validatePolicy(p); err != nil {
			return api.EffectivePolicy{}, err
		}
		p.SHA256, err = policyDigest(p)
		return p, err
	}
	sealed, err := resolve(approved.Context)
	if err != nil {
		return empty, err
	}
	if retained && sealed.SHA256 != approved.SHA256 {
		return empty, integrity("canonical sources differ from the approved policy digest")
	}
	selected, err := resolve(role)
	if err != nil {
		return empty, err
	}
	winners := map[string]api.SettingValue{}
	for _, setting := range baseline.settings {
		winners[setting.Key] = setting
	}
	for _, layer := range layers {
		pair := layer.layer.DefinedAt
		if pair != nil && pair.Level == role.Level && pair.Role == role.Role {
			for _, setting := range layer.settings {
				winners[setting.Key] = setting
			}
		}
	}
	result := CanonicalView{Policy: selected, Settings: []api.SettingValue{}, Names: []string{}, Resources: resources}
	for _, setting := range winners {
		result.Settings = append(result.Settings, setting)
	}
	for name := range roles {
		result.Names = append(result.Names, name)
	}
	sort.Slice(result.Settings, func(i, j int) bool { return result.Settings[i].Key < result.Settings[j].Key })
	sort.Strings(result.Names)
	return result, nil
}

func canonicalSettings(values []api.SettingValue, source api.SourceRef) ([]api.SettingValue, error) {
	result := make([]api.SettingValue, 0, len(values))
	seen := map[string]bool{}
	for _, item := range values {
		count := 0
		var value any
		if item.Boolean != nil {
			count++
			value = *item.Boolean
		}
		if item.Integer != nil {
			count++
			value = *item.Integer
		}
		if item.String != nil {
			count++
			value = *item.String
		}
		if item.Strings != nil {
			count++
			value = *item.Strings
		}
		if count != 1 || seen[item.Key] || item.Source != (api.SourceRef{}) && item.Source != source || settings.Validate(item.Key, value) != nil {
			return nil, invalid("canonical setting has an invalid type, key or defining source")
		}
		encoded, err := json.Marshal(value)
		if err != nil || credentialtext.HasCredential(string(encoded)) {
			return nil, invalid("canonical setting contains prohibited credential content")
		}
		item.Source = source
		seen[item.Key] = true
		result = append(result, item)
	}
	return result, nil
}
