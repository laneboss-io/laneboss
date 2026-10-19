package secrets

import (
	"bytes"
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestInstalledHumanPin(t *testing.T) {
	for _, mode := range []string{"initial", "life", "operation", "other_initial"} {
		t.Run(mode, func(t *testing.T) {
			c := newLaunchCase(t, "helper")
			operation := api.ID("initial-op-publication-a")
			// Reuse the complete enrolled runtime, including its executable
			// pins and empty arrays, rather than a partial runtime DTO.
			ref := c.store.objects["runtime-object"].Ref
			original, err := c.service.protectedObject(context.Background(), ref, "runtime-operation")
			if err != nil {
				t.Fatal("enrolled runtime control failed", err)
			}
			var enrolled api.RuntimeManifest
			if err := api.DecodeObject(original, &enrolled); err != nil {
				t.Fatal("enrolled runtime schema control failed", err)
			}
			marker := api.InitialPublicationMarker{Schema: "laneboss.initial-marker.v2", Config: c.service.deps.Config, ID: "publication-a", Manifest: ref}
			id := api.ID("initial-receipt-" + c.service.deps.Config)
			c.store.putObject(t, id, "manifest", marker, operation)
			meta := c.store.objects[id]
			meta.ACL.Audience = "human"
			c.store.objects[id] = meta
			meta = c.store.objects[ref.ID]
			meta.ACL.Audience = "human"
			meta.SourceOperationID = operation
			switch mode {
			case "life":
				meta.ACL.LifeID = c.target.LifeID
			case "operation":
				meta.SourceOperationID = "another-operation"
			case "other_initial":
				meta.SourceOperationID = "initial-op-publication-b"
			}
			c.store.objects[ref.ID] = meta
			// agentRuntime supplies the object's own operation and life. Those
			// self-matching arguments must not admit a foreign publication.
			data, err := c.service.protectedObjectFor(context.Background(), ref, meta.SourceOperationID, true, meta.ACL.LifeID)
			if mode == "initial" {
				want, readErr := c.service.protectedObject(context.Background(), ref, operation)
				stageCode(t, readErr, api.CodeForbidden)
				if err != nil || !bytes.Equal(data, original) || len(want) != 0 {
					t.Fatal("initial human manifest lost its installed-only read", err)
				}
				var runtime api.RuntimeManifest
				if api.DecodeObject(data, &runtime) != nil || runtime.Schema != "laneboss.runtime.v2" || runtime.Generation != 1 {
					t.Fatal("installed pin did not read the actual initial bytes")
				}
				if err := c.service.agentRuntime(context.Background(), ref, enrolled, enrolled.Bootstrap); err != nil {
					t.Fatal("initial publication lost the agent runtime path", err)
				}
				again, err := c.service.protectedObjectFor(context.Background(), ref, "", true)
				if err != nil || !bytes.Equal(data, again) {
					t.Fatal("installed worker read changed the initial bytes", err)
				}
				return
			}
			stageCode(t, err, api.CodeForbidden)
			if len(data) != 0 {
				t.Fatal("refused installed pin returned bytes")
			}
		})
	}
}
