package store

import (
	"context"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// This private source verifies the CURRENT protected manifest without reading
// vendor payloads. Only retained SQL history may turn a superseded pin into an
// absent, retain-only node; a reader's generic NotFound/Integrity never does.
type cleanupRuntimeManifestReader interface {
	ReadCleanupRuntimeManifest(context.Context) (api.BlobRef, api.RuntimeManifest, error)
}

type runtimeMeasurement struct {
	object api.CleanupObject
	state  string
}

type runtimeMeasurementResult struct {
	measurement runtimeMeasurement
	err         error
}

type runtimeMeasurements struct {
	mu        sync.Mutex
	store     *Service
	intent    api.ID
	claim     api.ID
	closed    bool
	values    map[api.BlobRef]runtimeMeasurementResult
	history   runtimeHistory
	loaded    bool
	manifest  api.BlobRef
	namespace api.RuntimeManifest
	available bool
}

type runtimeMeasurementsKey struct{}

// Always create a new cache at a top-level operation boundary, even when a
// caller supplies a context from an older verification. Closing destroys it.
func (s *Service) runtimeOperation(ctx context.Context, job api.CleanupJob) (context.Context, *runtimeMeasurements, func()) {
	cache := &runtimeMeasurements{store: s, intent: job.Intent.ID, claim: job.Claim.ClaimID, values: map[api.BlobRef]runtimeMeasurementResult{}}
	finish := func() {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		cache.closed, cache.values, cache.history = true, nil, nil
		cache.namespace = api.RuntimeManifest{}
	}
	return context.WithValue(ctx, runtimeMeasurementsKey{}, cache), cache, finish
}

func (s *Service) measuredRuntime(ctx context.Context, db readDatabase, ref api.BlobRef) (runtimeMeasurement, error) {
	cache, ok := ctx.Value(runtimeMeasurementsKey{}).(*runtimeMeasurements)
	if !ok || cache.store != s {
		cache = &runtimeMeasurements{store: s, values: map[api.BlobRef]runtimeMeasurementResult{}}
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return runtimeMeasurement{}, err
	}
	if cache.closed {
		return runtimeMeasurement{}, fault(api.CodeConflict, "runtime measurement operation has ended")
	}
	if saved, found := cache.values[ref]; found {
		return saved.measurement, saved.err
	}
	measurement, err := s.measureRuntime(ctx, db, ref, cache)
	cache.values[ref] = runtimeMeasurementResult{measurement, err}
	return measurement, err
}

func (s *Service) measureRuntime(ctx context.Context, db readDatabase, ref api.BlobRef, cache *runtimeMeasurements) (runtimeMeasurement, error) {
	reader, ok := s.deps.CleanupNative.(cleanupRuntimeReader)
	if !ok {
		return runtimeMeasurement{}, fault(api.CodeNotFound, "cleanup runtime namespace is not installed")
	}
	if !cache.loaded {
		var err error
		cache.history, err = s.retainedRuntimeHistory(ctx, db)
		if err != nil {
			return runtimeMeasurement{}, err
		}
		if source, ok := s.deps.CleanupNative.(cleanupRuntimeManifestReader); ok {
			cache.manifest, cache.namespace, err = source.ReadCleanupRuntimeManifest(ctx)
			if err != nil {
				return runtimeMeasurement{}, err
			}
			if !wire.ValidID(string(cache.manifest.ID)) || cache.manifest.Class != "manifest" || !wire.ValidDigest(string(cache.manifest.SHA256)) ||
				cache.manifest.Bytes <= 0 || cache.manifest.Bytes > api.MaxObjectBytes || cache.namespace.Schema != "laneboss.runtime.v2" ||
				cache.namespace.Generation == 0 || cache.namespace.Generation >= 1<<53 || len(cache.namespace.Objects) == 0 || len(cache.namespace.Objects) > 128 {
				return runtimeMeasurement{}, fault(api.CodeIntegrity, "installed runtime manifest observation is invalid")
			}
			cache.available = true
		}
		cache.loaded = true
	}
	provenance := cache.history[ref]
	if len(provenance) != 0 && cache.available {
		current := false
		for _, object := range cache.namespace.Objects {
			current = current || runtimeVendorPin(object) && object.Content == ref
		}
		if !current {
			if provenance[cache.manifest] {
				return runtimeMeasurement{}, fault(api.CodeIntegrity, "installed runtime contradicts its retained manifest bytes")
			}
			object, err := s.runtimeInventoryObject(ref)
			return runtimeMeasurement{object: object, state: "absent"}, err
		}
	}
	// Preserve the native reader's actual typed refusal, including unknown IDs
	// and same-ID/different-digest failures. They are never upgrade evidence.
	actual, err := reader.ReadCleanupRuntime(ctx, ref)
	if err != nil {
		return runtimeMeasurement{}, err
	}
	if actual.Ref != ref || ref.Class != "artifact" || ref.Bytes < 1 || ref.Bytes > api.MaxVendorBytes ||
		!wire.ValidID(string(actual.RootID)) || actual.RootID == s.storeID || actual.RootIdentity == "" || actual.Identity == "" ||
		actual.OwnerLifeID != "" || actual.OwnershipGeneration != 0 || actual.Role != "runtime" || actual.References != 0 {
		return runtimeMeasurement{}, fault(api.CodeIntegrity, "cleanup runtime measurement differs from its protected unowned file")
	}
	if len(provenance) == 0 {
		return runtimeMeasurement{}, fault(api.CodeIntegrity, "cleanup runtime pin has no retained service manifest history")
	}
	object, err := s.runtimeInventoryObject(ref)
	return runtimeMeasurement{object: object, state: "present"}, err
}
