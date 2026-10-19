// This executable assembles owned test inputs before installation. It is not
// linked into Laneboss and has no service, state writer or publication client.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/policy"
	"laneboss.io/laneboss/internal/v2/templates"
)

type sourceInput struct {
	ID   api.ID `json:"id"`
	Path string `json:"path"`
	Kind string `json:"kind"`
	Data []byte `json:"data"`
}
type input struct {
	Config       string                  `json:"config"`
	Runtime      api.BlobRef             `json:"runtime_ref"`
	RuntimeRaw   []byte                  `json:"runtime"`
	Sources      []sourceInput           `json:"sources"`
	Project      []byte                  `json:"project"`
	Task         []byte                  `json:"task"`
	Judge        api.JudgeConfig         `json:"judge"`
	ExpiresAt    api.Timestamp           `json:"expires_at"`
	Model        string                  `json:"model"`
	RealClaudock *api.Executable         `json:"real_claudock,omitempty"`
	RealClaude   *api.Executable         `json:"real_claude,omitempty"`
	Egress       bool                    `json:"egress_anthropic,omitempty"`
	Documents    []document              `json:"documents,omitempty"`
	Contexts     []api.RoleContext       `json:"contexts,omitempty"`
	Projects     []api.ProjectEnrollment `json:"projects,omitempty"`
	RootGrants   *api.RootGrantManifest  `json:"root_grants,omitempty"`
	Budget       *api.Budget             `json:"budget,omitempty"`
}
type document struct {
	Ref  api.BlobRef `json:"ref"`
	Data []byte      `json:"data"`
}
type output struct {
	Schema    string                          `json:"schema"`
	Initial   admin.InitialManifest           `json:"initial"`
	Ref       api.BlobRef                     `json:"ref"`
	Raw       []byte                          `json:"raw"`
	Documents []document                      `json:"documents"`
	Root      api.RootGrantRequest            `json:"root_request"`
	Lanes     map[api.Driver]api.StartRequest `json:"lanes"`
}

func digest(raw []byte) api.Digest {
	sum := sha256.Sum256(raw)
	return api.Digest(hex.EncodeToString(sum[:]))
}
func ref(id api.ID, class string, raw []byte) api.BlobRef {
	return api.BlobRef{ID: id, Class: class, SHA256: digest(raw), Bytes: int64(len(raw))}
}

func assemble(in input) (output, error) {
	var out output
	var runtime api.RuntimeManifest
	if err := api.DecodeObject(in.RuntimeRaw, &runtime); err != nil {
		return out, err
	}
	if in.Runtime != ref(in.Runtime.ID, "manifest", in.RuntimeRaw) || len(in.Sources) < 5 || len(in.Sources) > 64 || len(in.Project) == 0 || len(in.Task) == 0 || in.Model == "" || len(in.Documents) > 128 {
		return out, fmt.Errorf("fixture inputs are incomplete or runtime bytes differ")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(in.ExpiresAt))
	if err != nil || expires.UTC().Format(time.RFC3339Nano) != string(in.ExpiresAt) || !expires.After(time.Now()) || expires.After(time.Now().Add(2*time.Hour)) {
		return out, fmt.Errorf("fixture expiry is not a bounded current UTC time")
	}
	refs := []api.BlobRef{}
	seen := map[api.ID]api.BlobRef{}
	addRef := func(r api.BlobRef) error {
		if old, exists := seen[r.ID]; exists {
			if old != r {
				return fmt.Errorf("fixture object identity aliases different bytes")
			}
			return nil
		}
		seen[r.ID] = r
		refs = append(refs, r)
		return nil
	}
	for _, obj := range runtime.Objects {
		if obj.Role == "claudock" || obj.Role == "claude" {
			continue // Vendor pins name installation files, never store payloads.
		}
		if err := addRef(obj.Content); err != nil {
			return out, err
		}
	}
	add := func(id api.ID, class string, raw []byte) (api.BlobRef, error) {
		r := ref(id, class, raw)
		if _, exists := seen[id]; exists {
			return r, fmt.Errorf("fixture document repeats an existing object")
		}
		if err := addRef(r); err != nil {
			return r, err
		}
		out.Documents = append(out.Documents, document{r, raw})
		return r, nil
	}
	encode := func(id api.ID, value any) (api.BlobRef, error) {
		if tree, ok := value.(api.ObjectManifest); ok {
			if err := manifest.Object(tree); err != nil {
				return api.BlobRef{}, err
			}
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return api.BlobRef{}, err
		}
		return add(id, "manifest", raw)
	}
	if _, err := add(in.Runtime.ID, "manifest", in.RuntimeRaw); err != nil {
		return out, err
	}
	for _, doc := range in.Documents {
		if !manifest.ValidID(doc.Ref.ID) || doc.Ref != ref(doc.Ref.ID, doc.Ref.Class, doc.Data) ||
			(doc.Ref.Class != "artifact" && doc.Ref.Class != "manifest" && doc.Ref.Class != "task") ||
			len(doc.Data) > api.MaxObjectBytes || (len(doc.Data) == 0 && doc.Ref.Class != "artifact") {
			return out, fmt.Errorf("case document differs from its actual object bytes")
		}
		if _, err := add(doc.Ref.ID, doc.Ref.Class, doc.Data); err != nil {
			return out, err
		}
	}
	// An explicit main copy grant selects its enrolled case workspace. Do
	// not add an independent default source to that launch's materialization.
	var mainProject api.ProjectEnrollment
	if requested := in.RootGrants; requested != nil {
		for _, grant := range requested.Data {
			if grant.Destination != "/work/main" || grant.RelativePath != "." || grant.Delivery != "copy" {
				continue
			}
			for _, project := range in.Projects {
				if grant.SourceObjectID != project.Object.ID || grant.SourceSHA256 != project.Object.SHA256 || grant.HistoryScope != project.HistoryScope {
					continue
				}
				if mainProject.ProjectID != "" {
					return out, fmt.Errorf("case main workspace selection is ambiguous")
				}
				if seen[project.Object.ID] != project.Object {
					return out, fmt.Errorf("case main workspace differs from retained document bytes")
				}
				mainProject = project
			}
		}
	}
	caseWorkspace := mainProject.ProjectID != ""
	projects := append([]api.ProjectEnrollment{}, in.Projects...)
	if !caseWorkspace {
		projectBytes, err := add("serve-project-readme", "artifact", in.Project)
		if err != nil {
			return out, err
		}
		project, err := encode("serve-project", api.ObjectManifest{Schema: "laneboss.objects.v2",
			Entries: []api.ObjectEntry{{Path: "README.md", Kind: "file", Mode: 0444, Content: &projectBytes}}})
		if err != nil {
			return out, err
		}
		mainProject = api.ProjectEnrollment{ID: "serve-project-enrollment", Generation: 1, ProjectID: "serve-project",
			Object: project, Base: string(project.SHA256), HistoryScope: "tree"}
		projects = append([]api.ProjectEnrollment{mainProject}, projects...)
	}
	var agent api.Executable
	for _, obj := range runtime.Objects {
		if obj.Role == "serve-fixture-agent" {
			if agent.ID != "" || obj.Mode != 0555 {
				return out, fmt.Errorf("fixture agent runtime is ambiguous or not executable")
			}
			agent = api.Executable{ID: obj.ID, SHA256: obj.Content.SHA256, Version: in.Model}
		}
	}
	launch := api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: in.Config, Generation: 1,
		Projects: projects, Supervisor: &runtime.Artifact, Runtimes: []api.LaunchRuntime{}}
	for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
		executable := agent
		sessionExecutable := agent
		if driver == api.DriverClaudock && in.RealClaudock != nil {
			pin := *in.RealClaudock
			found := false
			for _, object := range runtime.Objects {
				found = found || object.ID == pin.ID && object.Role == "claudock" && object.Mode == 0555 && object.Content.SHA256 == pin.SHA256
			}
			if !found || pin.ID != "claudock" || pin.Version != "0.1.0" {
				return out, fmt.Errorf("real Claudock differs from runtime pins")
			}
			executable = pin
			if in.RealClaude == nil {
				return out, fmt.Errorf("real Claude session executable enrollment is required")
			}
			sessionExecutable = *in.RealClaude
		}
		selected := api.LaunchRuntime{EnrollmentID: api.ID("serve-runtime-" + string(driver)), Generation: 1,
			Backend: "linux-bwrap-landlock", Driver: driver, Executable: executable, SessionExecutable: sessionExecutable, Manifest: in.Runtime}
		if driver == api.DriverClaudock {
			if _, err := api.RuntimeSessionExecutable(selected, runtime); err != nil {
				return out, err
			}
		}
		launch.Runtimes = append(launch.Runtimes, selected)
	}
	if in.Egress {
		launch.Network = []api.NetworkEndpoint{{ID: "anthropic-api", Host: "api.anthropic.com", Protocol: "tcp", Port: 443}}
	}
	if err := api.ValidateLaunchEnrollment(launch, in.Config, in.Runtime); err != nil {
		return out, err
	}
	launchRef, err := encode("serve-launch", launch)
	if err != nil {
		return out, err
	}
	files := []api.ResourceFile{}
	entries := []api.ObjectEntry{}
	layers := templates.Layers{Generation: 1}
	var workflow templates.Source
	for index, src := range in.Sources {
		content, err := add(api.ID(string(src.ID)+"-content"), "artifact", src.Data)
		if err != nil {
			return out, err
		}
		source := api.SourceRef{ID: src.ID, Path: src.Path, SHA256: content.SHA256, Generation: 1}
		files = append(files, api.ResourceFile{Source: source, Content: content, Kind: src.Kind, Mode: 0444, RevisionGeneration: 1})
		copy := content
		entries = append(entries, api.ObjectEntry{Path: source.Path, Kind: "file", Mode: 0444, Content: &copy})
		selected := templates.Source{Ref: source, Bytes: src.Data}
		switch index {
		case 0:
			layers.Org = selected
		case 1:
			layers.OrgDrivers = selected
		case 2:
			workflow = selected
		case 3:
			layers.Local = &selected
		case 4:
			layers.Drivers = &selected
		}
	}
	l5 := api.RoleContext{Level: 5, Role: "supervisor"}
	if _, err := templates.Resolve(l5, layers); err != nil {
		return out, err
	}
	levels, roles := []int{5}, []string{l5.Role}
	contexts := map[api.RoleContext]bool{l5: true}
	for _, role := range in.Contexts {
		if contexts[role] || role.Level < 3 || role.Level > 6 || role.InstanceID != "" {
			return out, fmt.Errorf("case role context is duplicate or unsupported")
		}
		contexts[role] = true
		selected := layers
		selected.Local, selected.Drivers = nil, nil
		for _, src := range in.Sources[5:] {
			path := fmt.Sprintf(".laneboss/L%d/roles/%s", role.Level, role.Role)
			value := templates.Source{Ref: api.SourceRef{ID: src.ID, Path: src.Path,
				SHA256: digest(src.Data), Generation: 1}, Bytes: src.Data}
			if src.Path == path+".md" {
				selected.Local = &value
			}
			if src.Path == path+".toml" {
				selected.Drivers = &value
			}
		}
		if selected.Local == nil || selected.Drivers == nil {
			return out, fmt.Errorf("case context lacks its actual role sources")
		}
		if _, err := templates.Resolve(role, selected); err != nil {
			return out, err
		}
		if !slices.Contains(levels, role.Level) {
			levels = append(levels, role.Level)
		}
		if !slices.Contains(roles, role.Role) {
			roles = append(roles, role.Role)
		}
	}
	rules, err := templates.SeedRules(workflow, api.Thresholds{Match: .85, UncertainLow: .4, UncertainHigh: .6, CalibrationID: "serve-fixture-calibration"})
	if err != nil {
		return out, err
	}
	thresholds := api.Thresholds{Match: .85, UncertainLow: .4, UncertainHigh: .6, CalibrationID: "serve-fixture-calibration"}
	for index := range rules {
		rules[index].Source = api.SourceRef{}
		rules[index].Scope = api.RuleScope{Levels: levels, Roles: roles}
	}
	half, cutoff, exclusions := int64(3600), .5, []api.ID{}
	doc := policy.CanonicalDocument{Schema: "laneboss.policy-source.v2", Thresholds: thresholds, Rules: rules, Skip: []api.SkipEntry{}, Settings: []api.SettingValue{}, Judge: &in.Judge, GuidanceHalfLifeSeconds: &half, GuidanceMinRelevance: &cutoff, ProfileExclusions: &exclusions}
	canonicalRaw, err := json.Marshal(doc)
	if err != nil {
		return out, err
	}
	canonical, err := add("serve-canonical", "artifact", canonicalRaw)
	if err != nil {
		return out, err
	}
	canonicalRef := api.SourceRef{ID: "serve-canonical-source", Path: policy.CanonicalPath, SHA256: canonical.SHA256, Generation: 1}
	files = append(files, api.ResourceFile{Source: canonicalRef, Content: canonical, Kind: "policy", Mode: 0444, RevisionGeneration: 1})
	entries = append(entries, api.ObjectEntry{Path: canonicalRef.Path, Kind: "file", Mode: 0444, Content: &canonical})
	p, err := policy.Resolve(1, l5, []policy.Layer{{Source: canonicalRef, Thresholds: thresholds, Rules: rules, Skip: []api.SkipEntry{}}}, in.Judge, half)
	if err != nil {
		return out, err
	}
	policyRaw, err := json.Marshal(p)
	if err != nil {
		return out, err
	}
	if _, err := policy.ValidateInitial(policyRaw); err != nil {
		return out, err
	}
	policyRef, err := add("serve-policy", "manifest", policyRaw)
	if err != nil {
		return out, err
	}
	sourceManifest, err := encode("serve-source-tree", api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: entries})
	if err != nil {
		return out, err
	}
	ownership, err := encode("serve-ownership", api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}})
	if err != nil {
		return out, err
	}
	snapshot := api.OrgSnapshot{Ref: api.OrgSnapshotRef{OrgID: api.ID(in.Config), Generation: 1, ManifestSHA256: sourceManifest.SHA256},
		Config: in.Config, Sources: files, Derived: []api.ResourceFile{}, Renderer: runtime.Artifact, OwnershipManifest: ownership}
	if err := templates.ValidateInitialSources(in.Config, snapshot, l5); err != nil {
		return out, err
	}
	snapshotRef, err := encode("serve-sources", snapshot)
	if err != nil {
		return out, err
	}
	profiles := api.RootGrantManifest{Schema: "laneboss.root-grants.v2", Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{},
		Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}, Profiles: []api.ProfileGrant{},
		Data: []api.DataGrant{{SourceObjectID: mainProject.Object.ID, SourceSHA256: mainProject.Object.SHA256, RelativePath: ".", Access: "rw", Delivery: "copy",
			Destination: "/work/main", HistoryScope: mainProject.HistoryScope, ExpiresAt: in.ExpiresAt}}}
	for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
		profiles.Profiles = append(profiles.Profiles, api.ProfileGrant{ProfileID: api.ID("serve-profile-" + string(driver)),
			Driver: driver, Provider: "serve-fixture", ExpiresAt: in.ExpiresAt})
	}
	if in.Egress {
		profiles.Network = []api.NetworkGrant{{EndpointID: "anthropic-api", Mode: "internet", ExpiresAt: in.ExpiresAt}}
	}
	if in.RootGrants != nil {
		if in.Egress {
			return out, fmt.Errorf("explicit case grants and egress defaults cannot be combined")
		}
		base := profiles.Data
		profiles = *in.RootGrants
		// Additional case data retains the default workspace unless the case
		// has explicitly supplied that workspace's enrolled main copy grant.
		if !caseWorkspace {
			profiles.Data = append(append([]api.DataGrant{}, base...), profiles.Data...)
		}
	}
	if err := manifest.Root(profiles, time.Now()); err != nil {
		return out, err
	}
	profileRef, err := encode("serve-profiles", profiles)
	if err != nil {
		return out, err
	}
	task, err := add("serve-l5-task", "task", in.Task)
	if err != nil {
		return out, err
	}
	out.Initial = admin.InitialManifest{Schema: "laneboss.initial.v2", Config: in.Config, ID: api.ID("initial-" + in.Config), Generation: 1,
		Runtime: in.Runtime, Launch: launchRef, Policy: policyRef, Sources: snapshotRef, SourceManifest: sourceManifest,
		Profiles: profileRef, Task: task, L5: l5, L5Sources: api.RoleTemplateSources{
			Prompt:  api.TemplateSource{Source: files[3].Source, Content: files[3].Content},
			Drivers: api.TemplateSource{Source: files[4].Source, Content: files[4].Content}}, Objects: refs}
	out.Raw, err = json.Marshal(out.Initial)
	if err != nil {
		return out, err
	}
	out.Ref = ref("serve-initial", "manifest", out.Raw)
	budget := api.Budget{WallMS: 60000, CPUSeconds: 30, MemoryBytes: 268435456, Processes: 16, DiskBytes: 33554432, Currency: "USD"}
	if in.Budget != nil {
		budget = *in.Budget
	}
	out.Root = api.RootGrantRequest{Manifest: profileRef, Budget: budget}
	if err := manifest.RootInput(out.Root); err != nil {
		return out, err
	}
	out.Lanes = map[api.Driver]api.StartRequest{}
	for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
		model := in.Model
		if driver == api.DriverClaudock && in.RealClaudock != nil {
			model = "claude-sonnet-4-6"
		}
		out.Lanes[driver] = api.StartRequest{Lane: "serve-" + string(driver), ProjectID: mainProject.ProjectID, Level: 5, Role: l5.Role,
			Task: task, Driver: driver, Model: model, Effort: "low", Budget: budget, ExpectedPolicyGeneration: 1,
			Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{}, Secrets: []api.SecretDelegation{},
				Profiles: []api.ProfileDelegation{}, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}}
	}
	out.Schema = "laneboss.serve-initial-bundle.v1"
	return out, nil
}

func run() error {
	path := flag.String("input", "", "protected harness input file")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		return fmt.Errorf("one harness input file is required")
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var in input
	if err := api.DecodeObject(raw, &in); err != nil {
		return err
	}
	out, err := assemble(in)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func main() {
	if err := run(); err != nil {
		var typed *api.Error
		if !errors.As(err, &typed) {
			typed = &api.Error{Code: api.CodeInvalid, Owner: "lb-v2-serve", Message: "owned fixture bundle assembly failed",
				Instead: "Retain assembler inputs and repair the actual source or runtime pins."}
		}
		if err := json.NewEncoder(os.Stderr).Encode(typed); err != nil {
			os.Exit(2)
		}
		os.Exit(1)
	}
}
