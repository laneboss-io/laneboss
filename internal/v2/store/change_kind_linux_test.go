//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/templates"
)

func TestAddedRoleSources(t *testing.T) {
	s, deps, tx, _ := canonicalApplyFixture(t)
	ctx := context.Background()
	var base api.OrgSnapshot
	var change api.ChangeRequest
	if err := storedProjection(ctx, s.db, "org", api.ID(deps.Config), &base); err != nil {
		t.Fatal(err)
	}
	if err := storedProjection(ctx, s.db, "change", tx.Effects[0].ApplyChange.ChangeID, &change); err != nil {
		t.Fatal(err)
	}
	role := api.RoleContext{Level: 4, Role: string(testID(t))}
	root := ".laneboss/L4/roles/" + role.Role
	refs := map[string]api.BlobRef{}
	for _, file := range base.Sources {
		name := ""
		switch file.Source.Path {
		case templates.OrgTemplatePath:
			name = root + ".md"
		case templates.OrgDriversPath:
			name = root + ".toml"
		}
		if name != "" {
			ref := file.Content
			refs[name] = ref
			change.Files = append(change.Files, api.ResourceDelta{Path: name, Action: "add", Mode: file.Mode, After: &ref})
		}
	}
	if len(refs) != 2 {
		t.Fatal("fixture omitted its actual org template pair")
	}
	next, err := nextOrgSnapshot(orgApply{Snapshot: base, Change: change}, api.ChangeReceipt{})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := templates.SelectSources(api.Scope{Config: deps.Config}, next, role)
	if err != nil || selected.Local == nil || selected.LocalStatus != "present" {
		t.Fatal("published role pair cannot be selected by the approved template reader", err)
	}
	if selected.Local.Prompt.Source.Path != root+".md" || selected.Local.Prompt.Content != refs[root+".md"] ||
		selected.Local.Drivers.Source.Path != root+".toml" || selected.Local.Drivers.Content != refs[root+".toml"] ||
		selected.Local.Prompt.Source.Generation != next.Ref.Generation || selected.Local.Drivers.Source.Generation != next.Ref.Generation {
		t.Fatal("role selection lost its newly published source identities or content")
	}
}
