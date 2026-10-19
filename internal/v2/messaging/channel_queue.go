package messaging

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) enqueueChannel(ctx context.Context, scope api.Scope, from api.Lane, grants api.GrantSet, channel api.EnrolledChannel, input api.MailSendRequest, report bool, artifacts []api.BlobRef) (api.Mail, error) {
	if s.deps.Preparer == nil {
		return api.Mail{}, api.NotImplemented(owner, "channel.job.prepare")
	}
	if len(channel.Destinations) != 1 {
		return api.Mail{}, problem(api.CodePrerequisite, "mail requires one explicitly enrolled channel destination")
	}
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err != nil {
		return api.Mail{}, err
	}
	job, err := s.deps.Preparer.PrepareChannelJob(ctx, scope, api.ChannelPrepareRequest{OperationID: receipt.Operation.ID,
		ChannelGrantID: input.ChannelGrantID, DestinationID: channel.Destinations[0].ID})
	if err != nil {
		return api.Mail{}, err
	}
	if err := api.ValidateChannelJob(job); err != nil {
		return api.Mail{}, err
	}
	mail := api.Mail{ID: job.MailID, Sender: scope.Actor, ChannelGrantID: input.ChannelGrantID, Content: input.Content,
		Artifacts: append([]api.BlobRef{}, artifacts...), Generation: 1, Source: scope.Source, Status: "queued", Ask: input.Ask, ReplyTo: input.ReplyTo}
	raw, err := json.Marshal(mail)
	if err != nil {
		return api.Mail{}, err
	}
	event := api.Event{Schema: api.SchemaVersion, ID: derivedID("queued", scope), Config: scope.Config, Kind: "mail.queued", Actor: scope.Actor, RequestedBy: scope.Actor,
		RequestID: scope.Request.RequestID, OperationID: receipt.Operation.ID, LifeID: from.LifeID, Run: from.Run, ParentLifeID: from.ParentLifeID,
		RootLifeID: from.RootLifeID, StarterChain: append([]api.ID{}, from.StarterChain...), StarterEventSeq: from.StarterEventSeq, Origin: "service", Payload: raw}
	events := []api.Event{event}
	if report {
		event.ID, event.Kind = derivedID("report", scope), "report.submitted"
		events = append(events, event)
	}
	cause := api.InternalIntent{ID: derivedID("intent", scope), Kind: api.InternalMailDeliver, Config: scope.Config,
		Actor: api.Actor{Kind: "service", ID: "mail-delivery"}, RequestedBy: scope.Actor, CauseOperationID: receipt.Operation.ID,
		CauseRequestID: scope.Request.RequestID, EffectID: job.Lease.EffectID, Target: job.Lease.Target, CancellationEpoch: from.CancellationEpoch}
	commit, err := s.deps.Store.Transact(ctx, api.Transaction{Scope: scope, RawRequest: receipt.RawRequest,
		Compare: []api.Compare{{Kind: api.CompareLane, ID: from.LifeID, Generation: from.Generation}, {Kind: api.CompareGrants, ID: grants.ID, Generation: grants.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: from.LifeID, Epoch: from.CancellationEpoch}}},
		Writes:  api.StateWrites{Mail: []api.Mail{mail}, WorkerLeases: []api.WorkerLease{job.Lease}}, Events: events,
		Effects: []api.Effect{{ID: job.Lease.EffectID, OperationID: receipt.Operation.ID, Context: &cause, Channel: &job}}, Reply: &api.RPCReply{Result: raw}})
	if err != nil {
		return api.Mail{}, err
	}
	return committedMail(commit.Reply)
}
