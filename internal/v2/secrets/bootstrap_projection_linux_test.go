//go:build linux

package secrets

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type bootstrapRuntimeControl struct {
	api.HelperControl
	foreign bool
}

func (h *bootstrapRuntimeControl) ResolveRuntime(ctx context.Context, handoff api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	actual, err := h.HelperControl.ResolveRuntime(ctx, handoff)
	if err != nil {
		return actual, err
	}
	selected := handoff.Spec.Runner.Executable
	actual.Manifest.Objects = append(actual.Manifest.Objects, api.RuntimeObject{ID: selected.ID, Role: "agent", RootID: "component-root", RelativePath: "agent", Content: api.BlobRef{ID: "component-agent-object", Class: "artifact", Bytes: 1, SHA256: selected.SHA256}, Mode: 0555})
	if h.foreign {
		actual.Manifest.Bootstrap.ID = "foreign-gate-bootstrap"
	}
	return actual, nil
}

func TestProjectionBootstrap(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		name := "enrolled"
		if foreign {
			name = "foreign"
		}
		t.Run(name, func(t *testing.T) {
			m, _ := projectionCase(t)
			s := m.c.service
			preparedPlan := m.c.plan(t)
			preparedPlan.Phase = "spec_retained"
			m.c.setPlan(t, preparedPlan)
			s.deps.Helper = &bootstrapRuntimeControl{HelperControl: s.deps.Helper, foreign: foreign}
			err := s.projectionInputs(context.Background(), m.a.Request)
			material, preparedErr := s.PreparedSlotMaterial(context.Background(), m.a.Request.Handoff.Spec, m.a.Request.Handoff.Spec.Runner.Slot.ID)
			clear(material.Bytes)
			if !foreign {
				if err != nil || preparedErr != nil {
					t.Fatal("enrolled agent and gate bootstrap were refused", err, preparedErr)
				}
				return
			}
			var refusal *api.Error
			if !errors.As(err, &refusal) || refusal.Code != api.CodeForbidden {
				t.Fatal("agent object under a foreign gate bootstrap was accepted", err)
			}
			if !errors.As(preparedErr, &refusal) || refusal.Code != api.CodeForbidden {
				t.Fatal("prepared material accepted a foreign gate bootstrap", preparedErr)
			}
		})
	}
}
