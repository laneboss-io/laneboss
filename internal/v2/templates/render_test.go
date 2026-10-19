package templates_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/templates"
)

func digest(data []byte) api.Digest {
	return api.Digest(fmt.Sprintf("%x", sha256.Sum256(data)))
}

func asset(t *testing.T, names ...string) []byte {
	t.Helper()
	parts := append([]string{"..", "..", "..", "templates", "v2"}, names...)
	data, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func source(id, path string, data []byte) templates.Source {
	return templates.Source{
		Ref:   api.SourceRef{ID: api.ID(id), Path: path, SHA256: digest(data), Generation: 7},
		Bytes: bytes.Clone(data),
	}
}

func layers(t *testing.T) templates.Layers {
	t.Helper()
	body := source("role-source", ".laneboss/L3/roles/executor.md", asset(t, "roles", "L3", "executor.md"))
	drivers := source("role-drivers", ".laneboss/L3/roles/executor.toml", []byte("drivers = [\"codex\"]\n"))
	return templates.Layers{
		Generation: 7,
		Org:        source("org-source", templates.OrgTemplatePath, asset(t, "org", "default.md")),
		OrgDrivers: source("org-drivers", templates.OrgDriversPath, asset(t, "org", "drivers.toml")),
		Local:      &body, Drivers: &drivers,
	}
}

func fixture(t *testing.T) templates.RenderInput {
	t.Helper()
	context := api.RoleContext{Level: 3, Role: "executor"}
	resolved, err := templates.Resolve(context, layers(t))
	if err != nil {
		t.Fatal(err)
	}
	workflow := source("org-workflow", templates.WorkflowPath, asset(t, "org", "workflow.toml"))
	thresholds := api.Thresholds{Match: .85, UncertainLow: .4, UncertainHigh: .6, CalibrationID: "calibration-one"}
	rules, err := templates.SeedRules(workflow, thresholds)
	if err != nil {
		t.Fatal(err)
	}
	task := []byte("# Exact task\r\n\tInspect bytes: 測試\n{{.Scope}}\nlast line")
	return templates.RenderInput{
		Config: "case-templates", Role: resolved,
		Lane: api.Lane{LifeID: "life-child", ParentLifeID: "life-root", RootLifeID: "life-root",
			StarterChain: []api.ID{"life-root"}, StarterEventSeq: 3, Level: 3, Role: "executor",
			Session: api.Session{Driver: api.DriverCodex}, GrantSetID: "grant-set", PolicyGeneration: 9,
			Workspace: api.Workspace{ID: "workspace-one", LogicalCWD: "/work/main", Branch: "task-branch"}},
		Policy: api.EffectivePolicy{Generation: 9, SHA256: digest([]byte("policy")), Context: context,
			Rules: rules, Sources: []api.SourceRef{workflow.Ref}},
		Grants: api.GrantSet{ID: "grant-set", LifeID: "life-child", ParentLifeID: "life-root",
			SHA256: digest([]byte("grants")), PolicyGeneration: 9, Generation: 2,
			Data:      []api.DataGrant{{ID: "work-grant", Destination: "/work/main", Access: "rw", Delivery: "copy"}},
			Secrets:   []api.SecretGrant{{ID: "task-secret", Name: "EXAMPLE_TOKEN", Version: "one", SourceHandle: "secret-source-marker", Delivery: "env", Target: "EXAMPLE_TOKEN"}},
			Resources: []api.ResourceGrant{{ID: "test-resource", Provider: "example", SourceHandle: "resource-source-marker", MaxActive: 1}}},
		Task: api.BlobRef{ID: "task-one", Class: "task", Bytes: int64(len(task)), SHA256: digest(task)}, TaskBytes: task,
	}
}

func errorCode(t *testing.T, err error, expected api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != expected || typed.Instead == "" {
		t.Fatalf("wanted typed %s with recovery, got %v", expected, err)
	}
}

func TestRenderRetainsTaskAndScope(t *testing.T) {
	input := fixture(t)
	before, err := templates.Render(input)
	if err != nil {
		t.Fatal(err)
	}
	again, err := templates.Render(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.Markdown, again.Markdown) || !reflect.DeepEqual(before.Template, again.Template) {
		t.Fatal("identical inputs produced a different document")
	}
	if before.Template.RenderedSHA256 != digest(before.Markdown) ||
		before.Template.SourceSHA256 != digest(asset(t, "roles", "L3", "executor.md")) || before.Template.Generation != 7 {
		t.Fatal("template reference does not bind actual source and rendered bytes")
	}
	marker := []byte("## Assigned task\n\n")
	position := bytes.Index(before.Markdown, marker)
	if position < 0 || !bytes.Equal(before.Markdown[position+len(marker):], input.TaskBytes) {
		t.Fatal("assigned task was dropped, evaluated or normalized")
	}
	for _, expected := range []string{
		"Level: L3\nRole: executor\n", "Template generation: 7", "Policy generation: 9",
		"Report line: life-child → life-root", "Worktree: /work/main", "grant-set",
		"laneboss org blacklist list --config case-templates", "EXAMPLE_TOKEN", "Instead: laneboss box",
	} {
		if !bytes.Contains(before.Markdown, []byte(expected)) {
			t.Fatalf("missing scope fact %q", expected)
		}
	}
	for _, marker := range []string{"secret-source-marker", "resource-source-marker"} {
		if bytes.Contains(before.Markdown, []byte(marker)) {
			t.Fatal("a protected source handle entered the prompt")
		}
	}
	if input.Grants.Secrets[0].SourceHandle != "secret-source-marker" || input.Grants.Resources[0].SourceHandle != "resource-source-marker" {
		t.Fatal("render changed the service grant projection")
	}
	if len(before.Sources) != 5 {
		t.Fatal("source or policy provenance was dropped")
	}
}

func TestResolveOrgFallbackAndCopies(t *testing.T) {
	input := layers(t)
	input.Local, input.Drivers = nil, nil
	resolved, err := templates.Resolve(api.RoleContext{Level: 3, Role: "executor"}, input)
	if err != nil {
		t.Fatal(err)
	}
	retained := resolved.RetainedSources()
	if len(retained) != 2 || !bytes.Equal(retained[0].Bytes, input.Org.Bytes) {
		t.Fatal("missing local layer did not retain the org default")
	}
	input.Org.Bytes[0] = '!'
	retained[0].Bytes[0] = '?'
	view := fixture(t)
	view.Role = resolved
	document, err := templates.Render(view)
	if err != nil {
		t.Fatal(err)
	}
	if document.Template.SourceSHA256 != digest(asset(t, "org", "default.md")) ||
		!bytes.Contains(document.Markdown, asset(t, "org", "default.md")) {
		t.Fatal("caller mutation changed resolved source bytes")
	}
	if !bytes.Equal(resolved.RetainedSources()[0].Bytes, asset(t, "org", "default.md")) {
		t.Fatal("archive view exposed mutable internal bytes")
	}
}

func TestResolveRejectsBadSources(t *testing.T) {
	cases := []struct {
		name   string
		change func(*templates.Layers)
		code   api.ErrorCode
	}{
		{"hash", func(v *templates.Layers) { v.Local.Bytes[0] = '!' }, api.CodeIntegrity},
		{"generation", func(v *templates.Layers) { v.Local.Ref.Generation-- }, api.CodeConflict},
		{"wrong-role", func(v *templates.Layers) { v.Local.Ref.Path = ".laneboss/L3/roles/reviewer.md" }, api.CodeForbidden},
		{"wrong-level", func(v *templates.Layers) { v.Local.Ref.Path = ".laneboss/L4/roles/executor.md" }, api.CodeForbidden},
		{"malformed", func(v *templates.Layers) {
			v.Local.Bytes = []byte("# Invalid body\n")
			v.Local.Ref.SHA256 = digest(v.Local.Bytes)
		}, api.CodeInvalid},
		{"partial", func(v *templates.Layers) { v.Drivers = nil }, api.CodeInvalid},
		{"bare-claude", func(v *templates.Layers) {
			v.Drivers.Bytes = []byte("drivers = [\"claude\"]\n")
			v.Drivers.Ref.SHA256 = digest(v.Drivers.Bytes)
		}, api.CodeForbidden},
		{"driver-key", func(v *templates.Layers) {
			v.Drivers.Bytes = []byte("drivers = [\"codex\"]\nallow = [\"all\"]\n")
			v.Drivers.Ref.SHA256 = digest(v.Drivers.Bytes)
		}, api.CodeInvalid},
		{"widen", func(v *templates.Layers) {
			v.OrgDrivers.Bytes = []byte("drivers = [\"claudock-cli\"]\n")
			v.OrgDrivers.Ref.SHA256 = digest(v.OrgDrivers.Bytes)
		}, api.CodeForbidden},
		{"duplicate-id", func(v *templates.Layers) { v.Drivers.Ref.ID = v.Local.Ref.ID }, api.CodeInvalid},
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			input := layers(t)
			row.change(&input)
			result, err := templates.Resolve(api.RoleContext{Level: 3, Role: "executor"}, input)
			errorCode(t, err, row.code)
			if result != nil {
				t.Fatal("invalid source returned a usable resolved template")
			}
		})
	}
}

func TestRenderRejectsScopeDrift(t *testing.T) {
	cases := []struct {
		name   string
		change func(*templates.RenderInput)
		code   api.ErrorCode
	}{
		{"task-trim", func(v *templates.RenderInput) { v.TaskBytes = v.TaskBytes[:len(v.TaskBytes)-1] }, api.CodeIntegrity},
		{"task-hash", func(v *templates.RenderInput) { v.Task.SHA256 = digest([]byte("other")) }, api.CodeIntegrity},
		{"task-class", func(v *templates.RenderInput) { v.Task.Class = "artifact" }, api.CodeInvalid},
		{"wrong-role", func(v *templates.RenderInput) { v.Lane.Role = "reviewer" }, api.CodeForbidden},
		{"bare-driver", func(v *templates.RenderInput) { v.Lane.Session.Driver = api.Driver("claude") }, api.CodeForbidden},
		{"revoked", func(v *templates.RenderInput) { v.Grants.Revoked = true }, api.CodeIntegrity},
		{"grant-life", func(v *templates.RenderInput) { v.Grants.LifeID = "life-sibling" }, api.CodeIntegrity},
		{"policy-gen", func(v *templates.RenderInput) { v.Grants.PolicyGeneration++ }, api.CodeConflict},
		{"lineage", func(v *templates.RenderInput) { v.Lane.StarterChain = []api.ID{"life-sibling"} }, api.CodeIntegrity},
		{"missing-route", func(v *templates.RenderInput) { v.Policy.Rules[0].Instead = "" }, api.CodeIntegrity},
		{"source-path", func(v *templates.RenderInput) { v.Policy.Sources[0].Path = "../escape" }, api.CodeIntegrity},
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			input := fixture(t)
			row.change(&input)
			document, err := templates.Render(input)
			errorCode(t, err, row.code)
			if len(document.Markdown) != 0 || document.Template.ID != "" {
				t.Fatal("invalid scope returned a partial usable prompt")
			}
		})
	}
}

func TestRenderDoesNotSeedOrGateTools(t *testing.T) {
	input := fixture(t)
	input.Policy.Rules = []api.Rule{}
	input.TaskBytes = []byte("Run an unfamiliar ordinary local tool in /work/main.")
	input.Task.Bytes = int64(len(input.TaskBytes))
	input.Task.SHA256 = digest(input.TaskBytes)
	document, err := templates.Render(input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(document.Markdown, []byte("raw-codex-exec")) || len(input.Policy.Rules) != 0 {
		t.Fatal("render inserted implicit blacklist entries into an existing policy")
	}
	if !bytes.HasSuffix(document.Markdown, input.TaskBytes) {
		t.Fatal("ordinary tool task was changed")
	}
}

func TestSeedInventoryAndRoutes(t *testing.T) {
	input := fixture(t)
	if len(input.Policy.Rules) != 12 {
		t.Fatal("initial source did not retain exactly twelve entries")
	}
	seen := map[api.ID]bool{}
	for _, rule := range input.Policy.Rules {
		if seen[rule.ID] || rule.Instead == "" || rule.Critical || rule.Band != "refuse" || rule.Thresholds.Match != .85 {
			t.Fatal("seed identity, route or threshold provenance changed")
		}
		seen[rule.ID] = true
		if strings.HasPrefix(string(rule.ID), "raw-tmux-") &&
			(!strings.Contains(rule.Text, "agent session") || !strings.Contains(rule.Text, "Private build or test")) {
			t.Fatal("tmux seed does not preserve ordinary build sessions")
		}
	}
	data := asset(t, "org", "workflow.toml")
	for _, mutation := range []struct{ old, new string }{
		{"raw-codex-exec", "unknown-seed"},
		{"instead = \"laneboss box\"", "instead = \"raw cloud\""},
		{"critical = false", "critical = true"},
	} {
		changed := bytes.Replace(data, []byte(mutation.old), []byte(mutation.new), 1)
		if bytes.Equal(changed, data) {
			t.Fatal("seed negative control did not mutate its input")
		}
		_, err := templates.SeedRules(source("workflow", templates.WorkflowPath, changed), input.Policy.Rules[0].Thresholds)
		errorCode(t, err, api.CodeInvalid)
	}
}

func TestAllPublishedRolePairs(t *testing.T) {
	for _, row := range []struct {
		level int
		role  string
	}{
		{3, "executor"}, {3, "reviewer"}, {3, "tester"},
		{4, "supervisor"}, {5, "supervisor"}, {6, "supervisor"},
	} {
		t.Run(fmt.Sprintf("L%d-%s", row.level, row.role), func(t *testing.T) {
			input := layers(t)
			level := fmt.Sprintf("L%d", row.level)
			base := fmt.Sprintf(".laneboss/%s/roles/%s", level, row.role)
			body := source("role", base+".md", asset(t, "roles", level, row.role+".md"))
			drivers := source("drivers", base+".toml", asset(t, "roles", level, row.role+".toml"))
			input.Local, input.Drivers = &body, &drivers
			resolved, err := templates.Resolve(api.RoleContext{Level: row.level, Role: row.role}, input)
			if err != nil {
				t.Fatal(err)
			}
			if len(resolved.RetainedSources()) != 4 {
				t.Fatal("published role pair lost provenance")
			}
		})
	}
}

func TestLaneGroupsRetainCleaned(t *testing.T) {
	groups, err := templates.GroupLanes([]api.Lane{
		{LifeID: "running-z", State: "running"}, {LifeID: "running-a", State: "preparing"},
		{LifeID: "ended", State: "verifying"}, {LifeID: "accepted", State: "accepted"},
		{LifeID: "merged", State: "merged"}, {LifeID: "lost", State: "lost"},
		{LifeID: "idle", State: "idle"}, {LifeID: "cleaned", State: "merged", Cleaned: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := api.LaneGroups{Running: []api.ID{"running-a", "running-z"}, Ended: []api.ID{"ended"},
		Accepted: []api.ID{"accepted", "merged"}, Lost: []api.ID{"lost"}, Idle: []api.ID{"idle"}, Others: []api.ID{"cleaned"}}
	if !reflect.DeepEqual(groups, want) {
		t.Fatalf("unexpected lifecycle grouping: %+v", groups)
	}
	_, err = templates.GroupLanes([]api.Lane{{LifeID: "unknown", State: "new-state"}})
	errorCode(t, err, api.CodeIntegrity)
	_, err = templates.GroupLanes([]api.Lane{{LifeID: "duplicate", State: "idle"}, {LifeID: "duplicate", State: "idle"}})
	errorCode(t, err, api.CodeIntegrity)
}
