package store

import (
	"bytes"
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

type usageObjectKey struct{}
type usageObjectAuthority struct {
	Store  *Service
	Object api.ID
	Owner  api.Actor
	Life   api.ID
}

func (s *Service) usageRetention(ctx context.Context, scope api.Scope, request api.RetainObjectRequest) (context.Context, error) {
	if err := s.usageOwner(ctx, s.db, scope); err != nil {
		return ctx, err
	}
	stage, err := usageStageFor(ctx, s.db, request.Intent.ID)
	if err != nil {
		return ctx, err
	}
	if err := s.usageFence(ctx, s.db, stage.Job); err != nil {
		return ctx, err
	}
	object, job := request.Object, stage.Job
	if request.Intent != job.Cause || object.ACL.Owner != job.Actor || object.ACL.LifeID != job.Lease.Target.LifeID || object.ACL.Config != scope.Config || object.ACL.Generation != 1 || object.ACL.Audience != "service" || len(object.ACL.Participants) != 0 || object.Origin != "service" {
		return ctx, fault(api.CodeForbidden, "usage retention differs from its original worker ownership")
	}
	var ack dataAcknowledgement
	if err := storedProjection(ctx, s.db, "usage_ack", job.Lease.ID, &ack); err != nil {
		return ctx, err
	}
	var output struct {
		Raw        []byte        `json:"raw"`
		ExitCode   int           `json:"exit_code"`
		ObservedAt api.Timestamp `json:"observed_at"`
	}
	if err := api.DecodeObject(ack.Submission.Result, &output); err != nil {
		return ctx, err
	}
	switch object.Class {
	case "usage_raw":
		if !bytes.Equal(object.Bytes, output.Raw) || !sameValue(object.InputRefs, []api.BlobRef{job.Lease.Input, ack.Receipt.Result}) {
			return ctx, fault(api.CodeIntegrity, "usage raw bytes differ from their actual worker acknowledgement")
		}
	case "usage_window":
		var window api.UsageWindowEvidence
		if err := api.DecodeObject(object.Bytes, &window); err != nil {
			return ctx, err
		}
		if window.Target != job.Lease.Target || window.LaunchID != job.Input.Request.LaunchID || window.OperationID != job.Lease.OperationID || window.ProfileGrantID != job.Input.Request.ProfileGrantID || window.ProfileID != job.Input.Request.ProfileID || window.Provider != job.Input.Request.Provider || window.Executable != job.Input.Request.Executable || window.RuntimeManifest != job.Lease.RuntimeManifest || window.WorkerLeaseID != job.Lease.ID || window.ProducerID != job.Actor.ID || window.ObservedAt != output.ObservedAt || window.ExitCode != output.ExitCode || window.ID != object.ObjectKey || !sameValue(object.InputRefs, []api.BlobRef{window.Raw, ack.Receipt.Result}) {
			return ctx, fault(api.CodeIntegrity, "usage envelope differs from its actual native producer and input")
		}
		meta, raw, err := objectRow(ctx, s.db, window.Raw.ID)
		if err != nil {
			return ctx, err
		}
		if meta.Ref != window.Raw || meta.ACL.Owner != job.Actor || meta.ACL.Audience != "service" || !bytes.Equal(raw, output.Raw) {
			return ctx, fault(api.CodeIntegrity, "usage window lost its acknowledged original TSV")
		}
		if err := api.ValidateUsageSource(window, raw, job.Input.VendorProfile); err != nil {
			return ctx, err
		}
	default:
		return ctx, fault(api.CodeForbidden, "usage job cannot retain another private object class")
	}
	return context.WithValue(ctx, usageObjectKey{}, usageObjectAuthority{s, object.ObjectKey, job.Actor, job.Lease.Target.LifeID}), nil
}

func (s *Service) privateUsageObject(ctx context.Context, scope api.Scope, object api.ObjectWrite) bool {
	bound, ok := ctx.Value(usageObjectKey{}).(usageObjectAuthority)
	return ok && bound.Store == s && bound.Object == object.ObjectKey && scope.Connection == nil && scope.Actor.Kind == "service" &&
		object.ACL.Owner == bound.Owner && object.ACL.LifeID == bound.Life && object.ACL.Audience == "service" && object.ACL.Generation == 1 &&
		(object.Class == "usage_raw" || object.Class == "usage_window") && object.Origin == "service"
}
