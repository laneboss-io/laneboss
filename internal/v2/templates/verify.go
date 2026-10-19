package templates

import (
	"bytes"
	"fmt"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

// ValidateBriefing checks internal consistency of an authenticated service
// response. It neither authenticates the caller nor proves object retention.
// Source lookup, committed class metadata and approval remain service duties.
func ValidateBriefing(role api.RoleContext, briefing api.Briefing) error {
	if err := checkContext(role); err != nil {
		return err
	}
	if err := checkBlobRef(briefing.Markdown); err != nil {
		return integrity("briefing has no valid retained prompt reference")
	}
	if briefing.Markdown.Class != "prompt" || !safeID.MatchString(string(briefing.Template.ID)) ||
		!safeDigest.MatchString(string(briefing.Template.SourceSHA256)) ||
		briefing.Template.RenderedSHA256 != briefing.Markdown.SHA256 ||
		briefing.Template.Generation == 0 || briefing.Template.Generation > maxGeneration ||
		briefing.PolicyGeneration == 0 || briefing.PolicyGeneration > maxGeneration ||
		len(briefing.Sources) == 0 || len(briefing.Checks) == 0 {
		return integrity("briefing omits a retained prompt, template provenance or checks")
	}
	refs, err := mergeSources(nil, briefing.Sources)
	if err != nil {
		return err
	}
	if len(refs) != len(briefing.Sources) {
		return integrity("briefing repeats a consumed source reference")
	}
	var selected *api.SourceRef
	for index := range refs {
		if refs[index].ID == briefing.Template.ID {
			selected = &refs[index]
		}
	}
	if selected == nil || selected.SHA256 != briefing.Template.SourceSHA256 ||
		selected.Generation != briefing.Template.Generation {
		return integrity("briefing template differs from its selected source reference")
	}
	expected := fmt.Sprintf(".laneboss/L%d/roles/%s.md", role.Level, role.Role)
	if selected.Path != OrgTemplatePath && selected.Path != expected {
		return problem(api.CodeForbidden, "briefing template belongs to another level or role",
			"Use the authenticated lane's exact role or its approved org default.")
	}
	for _, check := range briefing.Checks {
		if !check.Available {
			return problem(api.CodePrerequisite, "briefing contains an unavailable capability",
				"Inspect the briefing checks and repair the prerequisite before launching.")
		}
	}
	seen := map[api.ID]bool{}
	for _, group := range [][]api.ID{briefing.LaneGroups.Running, briefing.LaneGroups.Ended,
		briefing.LaneGroups.Accepted, briefing.LaneGroups.Lost, briefing.LaneGroups.Idle, briefing.LaneGroups.Others} {
		for _, life := range group {
			if !safeID.MatchString(string(life)) || seen[life] {
				return integrity("briefing groups contain an invalid or repeated lane life")
			}
			seen[life] = true
		}
	}
	return nil
}

// VerifyPrompt checks actual bytes against an already-authorized briefing's
// metadata. A digest is evidence of byte identity, not that an agent read it.
func VerifyPrompt(role api.RoleContext, briefing api.Briefing, prompt []byte) error {
	if err := ValidateBriefing(role, briefing); err != nil {
		return err
	}
	if int64(len(prompt)) != briefing.Markdown.Bytes || hash(prompt) != briefing.Markdown.SHA256 {
		return integrity("briefing prompt differs from its retained length or digest")
	}
	if !utf8.Valid(prompt) || bytes.ContainsRune(prompt, 0) {
		return integrity("briefing prompt is not UTF-8 text without NUL bytes")
	}
	return nil
}

// VerifyTaskPrompt additionally compares the actual assigned task. The prompt
// format appends the exact task after a framing heading without a suffix. The
// rule-list reference must occur before that task, so task text cannot mask a
// missing discovery route in the launcher-supplied briefing.
func VerifyTaskPrompt(role api.RoleContext, briefing api.Briefing, task api.BlobRef,
	taskBytes, prompt []byte,
) error {
	if err := VerifyPrompt(role, briefing, prompt); err != nil {
		return err
	}
	if err := checkTask(task, taskBytes); err != nil {
		return err
	}
	start := len(prompt) - len(taskBytes)
	heading := []byte("## Assigned task\n\n")
	if start < len(heading) || !bytes.Equal(prompt[start:], taskBytes) ||
		!bytes.HasSuffix(prompt[:start], heading) {
		return integrity("rendered briefing did not retain the exact assigned task bytes")
	}
	if !bytes.Contains(prompt[:start], []byte("laneboss org blacklist list")) {
		return integrity("briefing omitted blacklist discovery before the assigned task")
	}
	return nil
}
