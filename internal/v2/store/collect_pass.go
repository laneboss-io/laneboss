package store

import (
	"context"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
)

// One independently verified pass pins its decoded record and object index.
// Every read still checks live authority and the writer's projection generation.
type collectionPass struct {
	mu         sync.Mutex
	loaded     bool
	generation api.Generation
	jobKey     string
	record     collectionRecord
	objects    map[api.ID]api.CleanupObject
}

// Caller holds the store read lock. No decoded record survives a writer change.
func (r collectionReads) current(ctx context.Context, job api.CleanupJob) (collectionRecord, error) {
	encoded, err := canonicalValue(job)
	if err != nil {
		return collectionRecord{}, err
	}
	key := hash(encoded)
	p := r.pass
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.loaded {
		saved, err := r.store.collectionJob(ctx, r.store.db, r.scope, job)
		if err != nil {
			return collectionRecord{}, err
		}
		if err := r.store.db.QueryRowContext(ctx, "SELECT generation FROM projections WHERE kind='collection' AND id=?", string(job.Intent.Cause.EffectID)).Scan(&p.generation); err != nil {
			return collectionRecord{}, err
		}
		p.jobKey, p.record, p.objects = key, saved, map[api.ID]api.CleanupObject{}
		if saved.Inventory != nil {
			for _, object := range saved.Inventory.Objects {
				p.objects[object.Ref.ID] = object
			}
		}
		p.loaded = true
		return saved, nil
	}
	if p.jobKey != key {
		return collectionRecord{}, fault(api.CodeConflict, "verification pass cannot change its original cleanup job")
	}
	if _, err := r.store.cleanClaim(ctx, r.store.db, r.scope, job.Claim); err != nil {
		return collectionRecord{}, err
	}
	var generation api.Generation
	if err := r.store.db.QueryRowContext(ctx, "SELECT generation FROM projections WHERE kind='collection' AND id=?", string(job.Intent.Cause.EffectID)).Scan(&generation); err != nil {
		return collectionRecord{}, err
	}
	if generation != p.generation {
		return collectionRecord{}, fault(api.CodeConflict, "cleanup record changed during independent verification")
	}
	return p.record, nil
}
