package grants

import (
	"context"
	"encoding/json"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

type enrollmentMetadata interface {
	WithMetadata(context.Context, func([]api.SecretInfo) error) error
}

type secretEnrollmentReader interface {
	ValidateSecretCapability(context.Context, api.Scope, api.SecretGrant) error
}

// GrantsEnroll is an operator mutation, never a root-resolution fallback.
// Its exact human proof, one immutable record and blob event commit together.
func (s *Service) GrantsEnroll(ctx context.Context, scope api.Scope, request api.CapabilityEnrollmentRequest) (result api.BlobRef, resultErr error) {
	ctx = verificationContext(ctx)
	if err := s.checkScope(ctx, scope); err != nil {
		return result, err
	}
	if scope.Actor.Kind != "human" {
		return result, refused("capability enrollment requires an independently confirmed human")
	}
	scope, view, err := s.freshAuthority(ctx, scope)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
	guard, err := s.humanMutation(ctx, scope, "grants.enroll", request)
	if err != nil {
		return result, err
	}
	if err := manifest.EnrollmentInput(request); err != nil {
		return result, err
	}
	if request.Resource != nil {
		grant := request.Resource.Grant()
		grant.SourceHandle, err = freshID()
		if err != nil {
			return result, err
		}
		return s.commitEnrollment(ctx, scope, grant.SourceHandle, grant, guard)
	}
	backend, ok := s.deps.Profiles.(enrollmentMetadata)
	reader, wired := s.deps.Store.(secretEnrollmentReader)
	if !ok || nilInterface(backend) || !wired || nilInterface(reader) {
		return result, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-grants",
			Message: "secret capability enrollment requires its protected source metadata and owner record"}
	}
	grant := request.Secret.Grant()
	called := false
	err = backend.WithMetadata(ctx, func(infos []api.SecretInfo) error {
		if called {
			return integrity("secret enrollment metadata callback repeated")
		}
		called = true
		matches := 0
		for _, info := range infos {
			if info.SourceHandle == request.Secret.SourceHandle {
				if info.Revoked || info.Name != request.Secret.Name || info.Version != request.Secret.Version {
					return refused("secret capability differs from its protected imported source")
				}
				matches++
			}
		}
		if matches != 1 {
			return refused("secret capability has no unique protected imported source")
		}
		if err := reader.ValidateSecretCapability(ctx, scope, grant); err != nil {
			return err
		}
		var err error
		result, err = s.commitEnrollment(ctx, scope, grant.SourceHandle, grant, guard)
		return err
	})
	if err != nil {
		return api.BlobRef{}, err
	}
	if !called || result.ID == "" {
		return api.BlobRef{}, integrity("secret enrollment produced no durable record")
	}
	return result, nil
}

func (s *Service) commitEnrollment(ctx context.Context, scope api.Scope, handle api.ID, value any, guard api.TransactionGuard) (result api.BlobRef, resultErr error) {
	check := emptyRootEnrollment()
	switch grant := value.(type) {
	case api.ResourceGrant:
		check.Resources = []api.ResourceGrant{grant}
	case api.SecretGrant:
		check.Secrets = []api.SecretGrant{grant}
	default:
		return result, integrity("unknown capability enrollment value")
	}
	if err := manifest.Root(check, s.deps.Clock.Now()); err != nil {
		return result, err
	}
	current, view, err := s.freshAuthority(ctx, scope)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
	if err := s.checkScope(ctx, current); err != nil {
		return result, err
	}
	policy, err := s.deps.Store.Policy(ctx, current)
	if err != nil {
		return result, err
	}
	if policy.Generation == 0 || policy.Generation != current.PolicyGeneration {
		return result, conflict("capability enrollment policy generation changed")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return result, integrity("cannot encode capability enrollment")
	}
	ref := api.BlobRef{ID: handle, Class: "manifest", Bytes: int64(len(raw)), SHA256: manifest.Hash(raw)}
	encoded, err := json.Marshal(ref)
	if err != nil {
		return result, err
	}
	eventID, err := freshID()
	if err != nil {
		return result, err
	}
	tx := api.Transaction{Scope: current, RawRequest: append([]byte(nil), scope.Frame.Bytes()...),
		Guards: []api.TransactionGuard{guard}, Reply: &api.RPCReply{Result: encoded},
		Writes: api.StateWrites{Objects: []api.ObjectWrite{{ObjectKey: handle, Class: "manifest", Bytes: raw, SHA256: ref.SHA256,
			ACL:    api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "owner", Generation: 1, Participants: []api.ID{}},
			Origin: "service", InputRefs: []api.BlobRef{}}}},
		Events: []api.Event{{Schema: api.SchemaVersion, ID: eventID, Config: scope.Config, Kind: "blob.committed",
			Actor: scope.Actor, RequestedBy: scope.Actor, RequestID: scope.Request.RequestID, Origin: "service", Payload: encoded}}}
	if err := api.ValidateTransactionShape(tx); err != nil {
		return result, err
	}
	commit, err := s.deps.Store.Transact(ctx, tx)
	if err != nil {
		return result, err
	}
	if commit.Reply != nil && commit.Reply.Error != nil {
		return result, commit.Reply.Error
	}
	if !manifest.ValidID(commit.Operation.ID) || commit.Operation.Status != "succeeded" || commit.FirstSeq == 0 || commit.LastSeq < commit.FirstSeq ||
		commit.Reply == nil || api.DecodeObject(commit.Reply.Result, &result) != nil || manifest.Blob(result) != nil || result.Class != "manifest" ||
		!commit.Replayed && result != ref {
		return api.BlobRef{}, integrity("capability enrollment has no exact durable record reply")
	}
	return result, nil
}
