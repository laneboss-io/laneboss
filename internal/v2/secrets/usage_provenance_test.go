package secrets

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestUsageProvenance(t *testing.T) {
	c, job := newUsageCase(t)
	ctx := context.Background()
	evidence, err := c.service.ReadUsageWindow(ctx, c.service.deps.ServiceScope, job.request)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := c.store.ObjectMetadata(ctx, c.service.deps.ServiceScope, evidence.ID)
	if err != nil {
		t.Fatal(err)
	}
	reader, ok := any(c.service).(api.UsageProvenanceSource)
	if !ok {
		t.Fatal("credential owner has no protected outside usage provenance reader")
	}
	scope := api.Scope{Config: c.service.deps.Config, Source: "watchdog", Actor: api.Actor{Kind: "watchdog", ID: "watchdog"}}
	first, err := reader.ReadUsageProvenance(ctx, scope, metadata.Ref)
	if err != nil || first.Evidence != metadata.Ref || first.Producer.Record.Actor.ID != evidence.ProducerID || first.VendorProfile != c.profile.Usage.VendorProfile {
		t.Fatal("usage reader lost actual producer or protected profile enrollment", err)
	}
	restarted, err := New(c.service.deps)
	if err != nil {
		t.Fatal(err)
	}
	reader, ok = any(restarted).(api.UsageProvenanceSource)
	if !ok {
		t.Fatal("restarted credential owner lost usage reader")
	}
	if actual, err := reader.ReadUsageProvenance(ctx, scope, metadata.Ref); err != nil || !reflect.DeepEqual(first, actual) {
		t.Fatal("usage provenance did not survive reconstruction", err)
	}
	for _, fault := range []string{"config", "actor", "ref", "missing", "producer", "run"} {
		t.Run(fault, func(t *testing.T) {
			selected, ref := scope, metadata.Ref
			switch fault {
			case "config":
				selected.Config += "-foreign"
			case "actor":
				selected.Actor.Kind = "lane"
			case "ref":
				ref.SHA256, err = valueDigest([]byte("different bytes"))
				if err != nil {
					t.Fatal(err)
				}
			case "missing":
				ref.ID = "unretained-usage"
			case "producer":
				c.store.fail["worker-binding"] = &api.Error{Code: api.CodeForbidden, Message: "component producer revoked"}
			case "run":
				c.store.lane.Run++
			}
			if _, err := reader.ReadUsageProvenance(ctx, selected, ref); err == nil {
				t.Fatal("usage provenance accepted a foreign replay or missing producer", fault)
			}
			delete(c.store.fail, "worker-binding")
		})
	}
}

func TestUsageProvenanceRefreshAfterBackoff(t *testing.T) {
	c, job := newRoomCase(t)
	ctx := context.Background()
	evidence, err := c.service.ReadUsageWindow(ctx, c.service.deps.ServiceScope, job.request)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := c.store.ObjectMetadata(ctx, c.service.deps.ServiceScope, evidence.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.clock.now = c.clock.now.Add(31 * time.Second)
	retained, err := c.service.ReadUsageProvenance(ctx, c.service.deps.ServiceScope, metadata.Ref)
	if err != nil || retained.Evidence != metadata.Ref {
		t.Fatal("backoff could not authenticate original metadata before a fresh query", err)
	}
	if err := api.ValidateUsageWindow(evidence, job.request, retained.Producer, c.clock.Now()); err == nil {
		t.Fatal("historical provenance relabelled old usage as fresh")
	}
	fresh, err := c.service.ReadUsageWindow(ctx, c.service.deps.ServiceScope, job.request)
	if err != nil || fresh.ID == evidence.ID || fresh.ObservedAt == evidence.ObservedAt || job.runs != 2 {
		t.Fatal("backoff did not acquire a new actual usage job", err)
	}
}

func TestUsageQueryReaders(t *testing.T) {
	for _, kind := range []string{"service", "watchdog"} {
		t.Run(kind, func(t *testing.T) {
			c, job := newUsageCase(t)
			scope := api.Scope{Config: c.service.deps.Config, Actor: api.Actor{Kind: kind, ID: "outside-reader"}, Source: kind}
			if _, err := c.service.ReadUsageWindow(context.Background(), scope, job.request); err != nil {
				t.Fatal("installed outside reader could not refresh actual from-profile usage", err)
			}
			scope.Connection, scope.Frame = job.scope.Connection, job.scope.Frame
			if _, err := c.service.ReadUsageWindow(context.Background(), scope, job.request); err == nil {
				t.Fatal("a public worker connection borrowed internal usage-reader authority")
			}
		})
	}
}
