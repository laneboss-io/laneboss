package store

import (
	"bytes"
	"context"
	"reflect"
	"slices"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
)

// CommitInitial is private installed-service publication. It uses the actual
// writer transaction and its atomic generation-zero compare; no database seed.
func (s *Service) CommitInitial(ctx context.Context, tx api.Transaction) (api.Commit, error) {
	if err := admin.VerifyInitialTransaction(ctx, tx); err != nil {
		return api.Commit{}, err
	}
	return s.Transact(s.initialProfileContext(ctx, tx), tx)
}

type initialProfileObjectKey struct{}
type initialProfileObjects struct {
	store   *Service
	scope   api.Scope
	objects map[api.ID]api.ObjectWrite
}

// Called only after the native administrator's exact transaction seal passed.
// Freeze only its generated profile observations, never a general service ACL.
func (s *Service) initialProfileContext(ctx context.Context, tx api.Transaction) context.Context {
	bound := initialProfileObjects{store: s, scope: tx.Scope, objects: map[api.ID]api.ObjectWrite{}}
	for _, object := range tx.Writes.Objects {
		if object.Class != "credential_evidence" {
			continue
		}
		object.Bytes = bytes.Clone(object.Bytes)
		object.ACL.Participants = slices.Clone(object.ACL.Participants)
		object.InputRefs = slices.Clone(object.InputRefs)
		bound.objects[object.ObjectKey] = object
	}
	return context.WithValue(ctx, initialProfileObjectKey{}, bound)
}

func (s *Service) privateInitialProfileObject(ctx context.Context, scope api.Scope, object api.ObjectWrite) bool {
	bound, ok := ctx.Value(initialProfileObjectKey{}).(initialProfileObjects)
	if !ok || bound.store != s || scope.Connection != nil || scope.Actor.Kind != "service" ||
		!reflect.DeepEqual(scope, bound.scope) || object.Class != "credential_evidence" ||
		object.ACL.Owner != scope.Actor || object.ACL.Config != scope.Config || object.ACL.LifeID != "" ||
		object.ACL.Generation != 1 || object.ACL.Audience != "service" || len(object.ACL.Participants) != 0 ||
		object.Origin != "service" || len(object.InputRefs) != 0 {
		return false
	}
	sealed, exists := bound.objects[object.ObjectKey]
	return exists && reflect.DeepEqual(sealed, object)
}
