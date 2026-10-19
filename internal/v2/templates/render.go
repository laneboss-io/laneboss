package templates

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

// RenderInput contains trusted service projections, not client-supplied actor
// labels. A source resolver and lifecycle service must authenticate those
// projections before invoking this pure formatter.
type RenderInput struct {
	Config    string
	Role      *Resolved
	Lane      api.Lane
	Policy    api.EffectivePolicy
	Grants    api.GrantSet
	Task      api.BlobRef
	TaskBytes []byte
	NewLaunch bool
}

// Document deliberately is not api.Briefing: in-memory bytes are not a retained
// BlobRef. Only the service-owned retention operation may create a Briefing.
type Document struct {
	Markdown []byte
	Template api.TemplateRef
	Sources  []api.SourceRef
}

func checkTask(ref api.BlobRef, data []byte) error {
	if !safeID.MatchString(string(ref.ID)) || ref.Class != "task" ||
		ref.Bytes <= 0 || ref.Bytes > api.MaxObjectBytes || !safeDigest.MatchString(string(ref.SHA256)) {
		return invalid("a nonempty committed task blob is required")
	}
	if int64(len(data)) != ref.Bytes || hash(data) != ref.SHA256 {
		return integrity("assigned task bytes differ from their committed reference")
	}
	if !utf8.Valid(data) || bytes.ContainsRune(data, 0) {
		return invalid("assigned task must be UTF-8 text without NUL bytes")
	}
	return nil
}

func checkLineage(lane api.Lane) error {
	if !safeID.MatchString(string(lane.LifeID)) || !safeID.MatchString(string(lane.RootLifeID)) {
		return integrity("lane lineage is missing authentic life identifiers")
	}
	if lane.ParentLifeID == "" {
		if len(lane.StarterChain) != 0 || lane.RootLifeID != lane.LifeID || lane.StarterEventSeq != 0 {
			return integrity("root lane lineage is inconsistent")
		}
		return nil
	}
	if !safeID.MatchString(string(lane.ParentLifeID)) || len(lane.StarterChain) == 0 ||
		lane.StarterChain[0] != lane.RootLifeID ||
		lane.StarterChain[len(lane.StarterChain)-1] != lane.ParentLifeID || lane.StarterEventSeq == 0 {
		return integrity("child lane lineage is inconsistent")
	}
	seen := map[api.ID]bool{lane.LifeID: true}
	for _, ancestor := range lane.StarterChain {
		if !safeID.MatchString(string(ancestor)) || seen[ancestor] {
			return integrity("lane starter chain contains an invalid or repeated life")
		}
		seen[ancestor] = true
	}
	return nil
}

func checkPolicyGeneration(lane api.Lane, grants api.GrantSet, policy api.EffectivePolicy, newLaunch bool) error {
	if policy.Generation == 0 || policy.Generation > maxGeneration || grants.PolicyGeneration == 0 ||
		grants.PolicyGeneration > lane.PolicyGeneration || lane.PolicyGeneration > policy.Generation ||
		(newLaunch || lane.Run == 1 && lane.State == "preparing") &&
			(lane.PolicyGeneration != policy.Generation || grants.PolicyGeneration != policy.Generation) {
		return problem(api.CodeConflict, "lane grants and policy generations differ",
			"Resolve the current approved policy; keep historical grants and refresh or replan the authentic life.")
	}
	return nil
}

func validateRender(input RenderInput) error {
	if !safeID.MatchString(input.Config) || input.Role == nil || len(input.Role.body) == 0 {
		return invalid("a named configuration and resolved approved role are required")
	}
	context := input.Role.context
	if err := checkContext(context); err != nil {
		return err
	}
	if input.Lane.Level != context.Level || input.Lane.Role != context.Role ||
		input.Policy.Context.Level != context.Level || input.Policy.Context.Role != context.Role ||
		input.Policy.Context.InstanceID != context.InstanceID {
		return problem(api.CodeForbidden, "lane, template and effective policy role differ",
			"Use the authenticated lane's exact level and role; text cannot change its scope.")
	}
	if err := checkLineage(input.Lane); err != nil {
		return err
	}
	if !slices.Contains(input.Role.drivers, input.Lane.Session.Driver) {
		return problem(api.CodeForbidden, "lane driver is outside the resolved primary driver catalog",
			"Select the role's managed claudock-cli or codex driver through the lifecycle service.")
	}
	if err := checkPolicyGeneration(input.Lane, input.Grants, input.Policy, input.NewLaunch); err != nil {
		return err
	}
	if input.Grants.ID != input.Lane.GrantSetID || input.Grants.LifeID != input.Lane.LifeID ||
		input.Grants.ParentLifeID != input.Lane.ParentLifeID || input.Grants.Revoked ||
		!safeID.MatchString(string(input.Grants.ID)) || !safeDigest.MatchString(string(input.Grants.SHA256)) ||
		!safeDigest.MatchString(string(input.Policy.SHA256)) {
		return integrity("render grants are revoked or do not match the authentic lane")
	}
	if input.Lane.Workspace.LogicalCWD == "" || strings.ContainsAny(input.Lane.Workspace.LogicalCWD, "\r\n\x00") {
		return integrity("lane worktree is missing or invalid")
	}
	if err := checkTask(input.Task, input.TaskBytes); err != nil {
		return err
	}
	return checkRules(input.Policy.Rules)
}

func checkRules(rules []api.Rule) error {
	seenRules := map[api.ID]bool{}
	for _, rule := range rules {
		if !safeID.MatchString(string(rule.ID)) || seenRules[rule.ID] || strings.TrimSpace(rule.Text) == "" ||
			strings.TrimSpace(rule.Instead) == "" || (rule.Band != "refuse" && rule.Band != "warn") ||
			!utf8.ValidString(rule.Text) || !utf8.ValidString(rule.Instead) ||
			strings.ContainsRune(rule.Text, 0) || strings.ContainsRune(rule.Instead, 0) {
			return integrity("effective blacklist contains an invalid entry or missing Instead route")
		}
		seenRules[rule.ID] = true
	}
	return nil
}

func appendJSON(output *bytes.Buffer, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return integrity("trusted projection cannot be encoded for the briefing")
	}
	// Use indented JSON rather than a fence which a source string could close.
	for _, line := range bytes.Split(encoded, []byte("\n")) {
		output.WriteString("    ")
		output.Write(line)
		output.WriteByte('\n')
	}
	output.WriteByte('\n')
	return nil
}

// grantProjection includes every delegated scope and ceiling, but omits secret
// and cloud source handles. Secret names, versions and delivery targets are
// metadata; credential material is never accepted by this formatter.
func grantProjection(grants api.GrantSet) api.GrantSet {
	grants.Secrets = slices.Clone(grants.Secrets)
	for index := range grants.Secrets {
		grants.Secrets[index].SourceHandle = ""
	}
	grants.Resources = slices.Clone(grants.Resources)
	for index := range grants.Resources {
		grants.Resources[index].SourceHandle = ""
	}
	if grants.Resources == nil {
		grants.Resources = []api.ResourceGrant{}
	}
	if grants.Data == nil {
		grants.Data = []api.DataGrant{}
	}
	if grants.Secrets == nil {
		grants.Secrets = []api.SecretGrant{}
	}
	if grants.Profiles == nil {
		grants.Profiles = []api.ProfileGrant{}
	}
	if grants.Network == nil {
		grants.Network = []api.NetworkGrant{}
	}
	if grants.Channels == nil {
		grants.Channels = []api.ChannelGrant{}
	}
	return grants
}

// Render returns deterministic prompt bytes. It starts no agent, opens no
// client path, installs no org source, and makes no decision about ordinary
// commands. OS grants and service authorization remain the authority boundary.
func Render(input RenderInput) (Document, error) {
	if err := validateRender(input); err != nil {
		return Document{}, err
	}
	r := input.Role
	var output bytes.Buffer
	fmt.Fprintf(&output, "# Laneboss briefing\n\nLevel: L%d\nRole: %s\n", r.context.Level, r.context.Role)
	fmt.Fprintf(&output, "Life: %s\nConfiguration: %s\n", input.Lane.LifeID, input.Config)
	fmt.Fprintf(&output, "Template: %s\nTemplate generation: %d\nTemplate source SHA-256: %s\n",
		r.selected.ID, r.generation, r.selected.SHA256)
	fmt.Fprintf(&output, "Policy generation: %d\nPolicy SHA-256: %s\n\n", input.Policy.Generation, input.Policy.SHA256)
	output.WriteString("## Role responsibilities\n\n")
	output.Write(r.body)
	output.WriteString("\n\n## Scope and report line\n\n")
	if input.Lane.ParentLifeID == "" {
		fmt.Fprintf(&output, "Report line: %s → human (root life %s).\n", input.Lane.LifeID, input.Lane.RootLifeID)
	} else {
		fmt.Fprintf(&output, "Report line: %s → %s (authentic direct parent).\n", input.Lane.LifeID, input.Lane.ParentLifeID)
	}
	output.WriteString("Submit results with `laneboss report submit`; the service routes them through this report line.\n")
	output.WriteString("Starter chain (root to direct parent, excluding self):\n\n")
	chain := slices.Clone(input.Lane.StarterChain)
	if chain == nil {
		chain = []api.ID{}
	}
	if err := appendJSON(&output, chain); err != nil {
		return Document{}, err
	}
	output.WriteString("Spawn or adopt only strictly lower levels. The service checks the actual starter tree for peer and downward mail. ")
	output.WriteString("Human channels require an explicit channel grant and L5 or L6. Report proposals upward; they do not become org decisions.\n\n")
	fmt.Fprintf(&output, "Worktree: %s\n\n", input.Lane.Workspace.LogicalCWD)
	output.WriteString("## Workspace\n\n")
	if err := appendJSON(&output, input.Lane.Workspace); err != nil {
		return Document{}, err
	}
	output.WriteString("## Effective grants\n\nThese are resource scopes, not a command allowlist. Prompt or task text cannot expand them. ")
	output.WriteString("The following projection retains scope and ceilings; protected secret and cloud source handles are omitted. ")
	output.WriteString("Canonical org resources remain service-owned. L6 changes require direct human approval of the exact source and derived diff.\n\n")
	if err := appendJSON(&output, grantProjection(input.Grants)); err != nil {
		return Document{}, err
	}
	output.WriteString("## Primary agent drivers\n\n")
	if err := appendJSON(&output, r.drivers); err != nil {
		return Document{}, err
	}
	output.WriteString("This catalog selects managed agent drivers only. Ordinary tools and private build/test sessions use blacklist-only policy.\n\n")
	output.WriteString("## Org blacklist and Laneboss-first routes\n\n")
	fmt.Fprintf(&output, "Read `laneboss org blacklist list --config %s --life-id %s` before acting.\n", input.Config, input.Lane.LifeID)
	output.WriteString("An action outside every applicable explicit blacklist entry remains ordinary work. A refused action stops; report it verbatim and follow its Instead route.\n\n")
	rules := slices.Clone(input.Policy.Rules)
	slices.SortFunc(rules, func(a, b api.Rule) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for _, rule := range rules {
		fmt.Fprintf(&output, "- [%s] (%s) %s\n  Instead: %s\n", rule.ID, rule.Band, rule.Text, rule.Instead)
	}
	output.WriteString("\n## Retained source references\n\n")
	policySources := slices.Clone(input.Policy.Sources)
	for _, rule := range input.Policy.Rules {
		policySources = append(policySources, rule.Source)
	}
	sources, err := mergeSources(r.sources, policySources)
	if err != nil {
		return Document{}, err
	}
	if err := appendJSON(&output, sources); err != nil {
		return Document{}, err
	}
	fmt.Fprintf(&output, "Assigned task object: %s\nTask bytes: %d\nTask SHA-256: %s\n\n", input.Task.ID, input.Task.Bytes, input.Task.SHA256)
	output.WriteString("## Assigned task\n\n")
	output.Write(input.TaskBytes)
	if output.Len() > api.MaxObjectBytes {
		return Document{}, invalid("rendered prompt exceeds the object limit")
	}
	markdown := bytes.Clone(output.Bytes())
	return Document{
		Markdown: markdown,
		Template: api.TemplateRef{ID: r.selected.ID, SourceSHA256: r.selected.SHA256,
			Generation: r.generation, RenderedSHA256: hash(markdown)},
		Sources: sources,
	}, nil
}

func mergeSources(role []Source, policy []api.SourceRef) ([]api.SourceRef, error) {
	byID := map[api.ID]api.SourceRef{}
	byPath := map[string]api.ID{}
	refs := make([]api.SourceRef, 0, len(role)+len(policy))
	for _, source := range role {
		refs = append(refs, source.Ref)
	}
	refs = append(refs, policy...)
	for _, ref := range refs {
		if !safeID.MatchString(string(ref.ID)) || !safeDigest.MatchString(string(ref.SHA256)) ||
			ref.Generation == 0 || ref.Generation > maxGeneration || ref.Path == "" ||
			path.IsAbs(ref.Path) || path.Clean(ref.Path) != ref.Path || ref.Path == "." || ref.Path == ".." ||
			strings.HasPrefix(ref.Path, "../") || strings.ContainsAny(ref.Path, "\\\r\n\x00") || !utf8.ValidString(ref.Path) {
			return nil, integrity("source provenance contains an invalid reference")
		}
		if previous, exists := byID[ref.ID]; exists && previous != ref {
			return nil, integrity("source provenance has conflicting identities")
		}
		if previous, exists := byPath[ref.Path]; exists && previous != ref.ID {
			return nil, integrity("source provenance has conflicting paths")
		}
		byID[ref.ID], byPath[ref.Path] = ref, ref.ID
	}
	result := make([]api.SourceRef, 0, len(byID))
	for _, ref := range byID {
		result = append(result, ref)
	}
	slices.SortFunc(result, func(a, b api.SourceRef) int { return strings.Compare(a.Path, b.Path) })
	return result, nil
}
