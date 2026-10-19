package templates_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/templates"
)

func rendered(t *testing.T, input templates.RenderInput) templates.Document {
	t.Helper()
	document, err := templates.Render(input)
	if err != nil {
		t.Fatalf("valid input could not be rendered: %v", err)
	}
	return document
}

func sectionJSON(t *testing.T, markdown []byte, heading string, result any) {
	t.Helper()
	marker := []byte("## " + heading + "\n\n")
	start := bytes.Index(markdown, marker)
	if start < 0 {
		t.Fatalf("missing structured section: %s", heading)
	}
	section := markdown[start+len(marker):]
	if end := bytes.Index(section, []byte("\n## ")); end >= 0 {
		section = section[:end]
	}
	var data bytes.Buffer
	for _, line := range bytes.Split(section, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("    ")) {
			data.Write(line[4:])
			data.WriteByte('\n')
		}
	}
	if err := json.Unmarshal(data.Bytes(), result); err != nil {
		t.Fatalf("structured section has no complete JSON: %s", heading)
	}
}

func TestTplSelectedContext(t *testing.T) {
	for _, selected := range []api.RoleContext{
		{Level: 3, Role: "executor"}, {Level: 3, Role: "reviewer"},
		{Level: 4, Role: "supervisor"}, {Level: 5, Role: "supervisor"},
		{Level: 6, Role: "supervisor"},
	} {
		t.Run(fmt.Sprintf("L%d-%s", selected.Level, selected.Role), func(t *testing.T) {
			input := fixture(t)
			level := fmt.Sprintf("L%d", selected.Level)
			pair := layers(t)
			base := fmt.Sprintf(".laneboss/%s/roles/%s", level, selected.Role)
			body := source("selected-role", base+".md", asset(t, "roles", level, selected.Role+".md"))
			drivers := source("selected-drivers", base+".toml", asset(t, "roles", level, selected.Role+".toml"))
			pair.Local, pair.Drivers = &body, &drivers
			resolved, err := templates.Resolve(selected, pair)
			if err != nil {
				t.Fatal(err)
			}
			input.Role = resolved
			input.Lane.Level, input.Lane.Role = selected.Level, selected.Role
			input.Policy.Context = selected
			document := rendered(t, input)
			header := fmt.Sprintf("Level: L%d\nRole: %s\n", selected.Level, selected.Role)
			if !bytes.Contains(document.Markdown, []byte(header)) {
				t.Fatal("selected level or role changed in prompt")
			}
		})
	}
}

func TestTplExactTask(t *testing.T) {
	for _, task := range [][]byte{
		[]byte(" leading whitespace\r\n\tUnicode: 確認\n{{.Task}}\nno final newline"),
		[]byte("## Assigned task\n\nNested headings stay literal.\n\n"),
		[]byte("x"),
	} {
		input := fixture(t)
		input.TaskBytes = bytes.Clone(task)
		input.Task.Bytes, input.Task.SHA256 = int64(len(task)), digest(task)
		document := rendered(t, input)
		prefix := []byte("## Assigned task\n\n")
		position := len(document.Markdown) - len(task)
		if position < len(prefix) || !bytes.Equal(document.Markdown[position:], task) ||
			!bytes.HasSuffix(document.Markdown[:position], prefix) {
			t.Fatal("assigned task bytes changed in rendered prompt")
		}
	}
}

func TestTplTemplateBinding(t *testing.T) {
	input := fixture(t)
	pair := layers(t)
	document := rendered(t, input)
	if document.Template.ID != pair.Local.Ref.ID ||
		document.Template.SourceSHA256 != digest(pair.Local.Bytes) ||
		document.Template.Generation != pair.Generation {
		t.Fatal("template reference lost source identity or generation")
	}
	for _, fact := range []string{
		fmt.Sprintf("Template generation: %d\n", pair.Generation),
		fmt.Sprintf("Template source SHA-256: %s\n", digest(pair.Local.Bytes)),
	} {
		if !bytes.Contains(document.Markdown, []byte(fact)) {
			t.Fatal("printed template provenance differs from selected source")
		}
	}
}

func TestTplRenderedHash(t *testing.T) {
	document := rendered(t, fixture(t))
	if document.Template.RenderedSHA256 != digest(document.Markdown) {
		t.Fatal("rendered hash does not bind actual prompt bytes")
	}
}

func TestTplGrantProjection(t *testing.T) {
	input := fixture(t)
	input.Grants.Data[0].RelativePath = "src"
	input.Grants.Data[0].Delegate = true
	input.Grants.Data[0].ExpiresAt = "2030-01-01T00:00:00Z"
	input.Grants.Network = []api.NetworkGrant{{ID: "net-one", EndpointID: "public-net", Mode: "internet", Delegate: false}}
	input.Grants.Profiles = []api.ProfileGrant{{ID: "profile-one", ProfileID: "provider-one", Driver: api.DriverCodex, Paid: false}}
	input.Grants.Channels = []api.ChannelGrant{{ID: "channel-one", ChannelID: "report-channel", Delegate: false}}
	input.Grants.Resources[0].Regions = []string{"example-region"}
	input.Grants.Resources[0].ImageIDs = []string{"image-one"}
	input.Grants.Resources[0].MachineTypes = []string{"small"}
	input.Grants.Resources[0].TotalBudgetMicros = 120
	before, err := json.Marshal(input.Grants)
	if err != nil {
		t.Fatal(err)
	}
	var expected api.GrantSet
	if err := json.Unmarshal(before, &expected); err != nil {
		t.Fatal(err)
	}
	expected.Secrets[0].SourceHandle = ""
	expected.Resources[0].SourceHandle = ""
	document := rendered(t, input)
	var projected api.GrantSet
	sectionJSON(t, document.Markdown, "Effective grants", &projected)
	if !reflect.DeepEqual(projected, expected) {
		t.Fatal("printed grants dropped or widened a delegated scope")
	}
	after, err := json.Marshal(input.Grants)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("render modified the authoritative input grants")
	}
}

func TestTplReportLine(t *testing.T) {
	input := fixture(t)
	input.Lane.ParentLifeID = "life-middle"
	input.Lane.StarterChain = []api.ID{input.Lane.RootLifeID, input.Lane.ParentLifeID}
	input.Grants.ParentLifeID = input.Lane.ParentLifeID
	document := rendered(t, input)
	line := fmt.Sprintf("Report line: %s → %s (authentic direct parent).\n", input.Lane.LifeID, input.Lane.ParentLifeID)
	if !bytes.Contains(document.Markdown, []byte(line)) {
		t.Fatal("report line did not name the authentic direct parent")
	}
	input.Lane.ParentLifeID, input.Grants.ParentLifeID = "", ""
	input.Lane.RootLifeID = input.Lane.LifeID
	input.Lane.StarterChain, input.Lane.StarterEventSeq = []api.ID{}, 0
	root := rendered(t, input)
	line = fmt.Sprintf("Report line: %s → human (root life %s).\n", input.Lane.LifeID, input.Lane.LifeID)
	if !bytes.Contains(root.Markdown, []byte(line)) {
		t.Fatal("human-started root report line changed")
	}
}

func TestTplWorkspace(t *testing.T) {
	input := fixture(t)
	input.Lane.Workspace.ProjectID = "project-one"
	input.Lane.Workspace.Base = "base-ref"
	input.Lane.Workspace.Snapshot = api.BlobRef{ID: "work-snapshot", Class: "manifest", SHA256: digest([]byte("snapshot")), Bytes: 8}
	document := rendered(t, input)
	var workspace api.Workspace
	sectionJSON(t, document.Markdown, "Workspace", &workspace)
	if !reflect.DeepEqual(workspace, input.Lane.Workspace) ||
		!bytes.Contains(document.Markdown, []byte("Worktree: "+input.Lane.Workspace.LogicalCWD+"\n")) {
		t.Fatal("selected workspace or worktree changed in prompt")
	}
}

func TestTplSourceRefs(t *testing.T) {
	input := fixture(t)
	// A rule may identify a distinct consumed source even when the config-level
	// source list contains only the org layer. Its provenance cannot disappear.
	ref := source("role-rule-source", ".laneboss/L3/policy.toml", []byte("role policy source")).Ref
	input.Policy.Rules[0].Source = ref
	document := rendered(t, input)
	found := false
	for _, actual := range document.Sources {
		if actual == ref {
			found = true
		}
	}
	if !found {
		t.Fatal("consumed rule source disappeared from provenance")
	}
	var printed []api.SourceRef
	sectionJSON(t, document.Markdown, "Retained source references", &printed)
	if !reflect.DeepEqual(printed, document.Sources) {
		t.Fatal("printed source references differ from retained references")
	}
}

func TestTplOrgFallback(t *testing.T) {
	pair := layers(t)
	pair.Local, pair.Drivers = nil, nil
	resolved, err := templates.Resolve(api.RoleContext{Level: 3, Role: "executor"}, pair)
	if err != nil {
		t.Fatalf("missing local layer rejected the org default: %v", err)
	}
	input := fixture(t)
	input.Role = resolved
	document := rendered(t, input)
	if document.Template.ID != pair.Org.Ref.ID || document.Template.SourceSHA256 != digest(pair.Org.Bytes) ||
		!bytes.Contains(document.Markdown, pair.Org.Bytes) {
		t.Fatal("missing local layer did not inherit org source bytes")
	}
}

func TestTplPartialLocal(t *testing.T) {
	pair := layers(t)
	pair.Local = nil
	resolved, err := templates.Resolve(api.RoleContext{Level: 3, Role: "executor"}, pair)
	if err == nil || resolved != nil {
		t.Fatal("orphan local driver source was silently inherited")
	}
	errorCode(t, err, api.CodeInvalid)
}

func TestTplTaskLength(t *testing.T) {
	input := fixture(t)
	input.Task.Bytes++
	_, err := templates.Render(input)
	if err == nil {
		t.Fatal("task byte count mismatch was accepted")
	}
	errorCode(t, err, api.CodeIntegrity)
}

func TestTplRuleListRoute(t *testing.T) {
	input := fixture(t)
	document := rendered(t, input)
	route := fmt.Sprintf("laneboss org blacklist list --config %s --life-id %s", input.Config, input.Lane.LifeID)
	if !bytes.Contains(document.Markdown, []byte(route)) {
		t.Fatal("briefing lost its scoped blacklist discovery route")
	}
}

func TestTplPrimaryCatalog(t *testing.T) {
	pair := layers(t)
	pair.Local, pair.Drivers = nil, nil
	pair.OrgDrivers.Bytes = []byte("drivers = [\"claude\"]\n")
	pair.OrgDrivers.Ref.SHA256 = digest(pair.OrgDrivers.Bytes)
	resolved, err := templates.Resolve(api.RoleContext{Level: 3, Role: "executor"}, pair)
	if err == nil || resolved != nil {
		t.Fatal("primary catalog accepted bare Claude")
	}
	errorCode(t, err, api.CodeForbidden)
}

func seedThresholds() api.Thresholds {
	return api.Thresholds{Match: .85, UncertainLow: .4, UncertainHigh: .6, CalibrationID: "calibration-one"}
}

func TestTplSeedCount(t *testing.T) {
	data := asset(t, "org", "workflow.toml")
	parts := bytes.Split(data, []byte("[[blacklist]]"))
	if len(parts) != 13 {
		t.Fatal("published seed source changed its stanza inventory")
	}
	changed := bytes.Join(append([][]byte{parts[0]}, parts[2:]...), []byte("[[blacklist]]"))
	_, err := templates.SeedRules(source("workflow", templates.WorkflowPath, changed), seedThresholds())
	if err == nil {
		t.Fatal("seed count guard accepted a missing workflow entry")
	}
	errorCode(t, err, api.CodeInvalid)
}

func TestTplSeedRoutes(t *testing.T) {
	data := asset(t, "org", "workflow.toml")
	parts := strings.Split(string(data), "[[blacklist]]")
	for index := 1; index < len(parts); index++ {
		t.Run(fmt.Sprintf("entry-%02d", index), func(t *testing.T) {
			copyParts := append([]string{}, parts...)
			lines := strings.Split(copyParts[index], "\n")
			changed := false
			for line := range lines {
				if strings.HasPrefix(lines[line], "instead = ") {
					lines[line] = "instead = \"another workflow\""
					changed = true
				}
			}
			if !changed {
				t.Fatal("seed route control did not change its input")
			}
			copyParts[index] = strings.Join(lines, "\n")
			input := []byte(strings.Join(copyParts, "[[blacklist]]"))
			_, err := templates.SeedRules(source("workflow", templates.WorkflowPath, input), seedThresholds())
			if err == nil {
				t.Fatal("seed parser accepted a changed Instead route")
			}
			errorCode(t, err, api.CodeInvalid)
		})
	}
}

func TestTplTmuxScope(t *testing.T) {
	parts := strings.Split(string(asset(t, "org", "workflow.toml")), "[[blacklist]]")
	for index := 1; index < len(parts); index++ {
		if !strings.Contains(parts[index], "id = \"raw-tmux-") {
			continue
		}
		lines := strings.Split(parts[index], "\n")
		for line := range lines {
			if strings.HasPrefix(lines[line], "text = ") {
				lines[line] = "text = \"Every private tmux session is forbidden.\""
			}
		}
		copyParts := append([]string{}, parts...)
		copyParts[index] = strings.Join(lines, "\n")
		input := []byte(strings.Join(copyParts, "[[blacklist]]"))
		_, err := templates.SeedRules(source("workflow", templates.WorkflowPath, input), seedThresholds())
		if err == nil {
			t.Fatal("tmux seed accepted a ban on ordinary private sessions")
		}
		errorCode(t, err, api.CodeInvalid)
		return
	}
	t.Fatal("no tmux seed was reached by the control")
}

func TestTplOrdinaryWork(t *testing.T) {
	input := fixture(t)
	input.Policy.Rules = []api.Rule{}
	input.TaskBytes = []byte("Use an unfamiliar local formatter in the selected worktree.")
	input.Task.Bytes, input.Task.SHA256 = int64(len(input.TaskBytes)), digest(input.TaskBytes)
	document, err := templates.Render(input)
	if err != nil {
		t.Fatalf("ordinary work was blocked by empty rules: %v", err)
	}
	if !bytes.HasSuffix(document.Markdown, input.TaskBytes) || len(input.Policy.Rules) != 0 {
		t.Fatal("ordinary task or empty blacklist was rewritten")
	}
}

func TestTplBriefingReadOnly(t *testing.T) {
	service, store, _, scope, _ := component(t)
	store.inputError = api.NotImplemented("lb-v2-service", "fixture briefing input")
	result, err := service.BriefStart(context.Background(), scope,
		api.BriefingRequest{Level: scope.Actor.Level, Role: scope.Actor.Role})
	if store.writes != 0 {
		t.Fatal("briefing changed state before input resolution")
	}
	if err == nil || result.Markdown.ID != "" {
		t.Fatal("unavailable briefing inputs produced a successful prompt")
	}
	errorCode(t, err, api.CodeNotImplemented)
}
