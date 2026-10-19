package messaging

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

func derivedID(kind string, scope api.Scope) api.ID {
	domain := []string{
		"laneboss.mail.v2", scope.Config, scope.Actor.Kind, string(scope.Actor.ID),
		string(scope.Actor.LifeID), string(scope.Request.Method), string(scope.Request.IdempotencyKey),
	}
	digest := sha256.Sum256([]byte(strings.Join(domain, "\x00")))
	return api.ID(kind + "-" + hex.EncodeToString(digest[:]))
}

func (s *Service) enqueue(ctx context.Context, scope api.Scope, request api.MailSendRequest, report bool, artifacts []api.BlobRef) (api.Mail, error) {
	if mail, found, err := s.replayMail(ctx, scope); found || err != nil {
		return mail, err
	}
	var from api.Lane
	var comparisons []api.Compare
	if scope.Actor.Kind == "lane" {
		var err error
		from, err = s.currentSender(ctx, scope)
		if err != nil {
			return api.Mail{}, err
		}
		grants, err := s.currentGrants(ctx, scope, from)
		if err != nil {
			return api.Mail{}, err
		}
		comparisons = append(comparisons,
			api.Compare{Kind: "lane", ID: from.LifeID, Generation: from.Generation},
			api.Compare{Kind: "grants", ID: grants.ID, Generation: grants.Generation},
		)
		if request.ChannelGrantID != "" {
			grant, err := s.channel(grants, from, request.ChannelGrantID)
			if err != nil {
				return api.Mail{}, err
			}
			channel, err := s.enrolledChannel(ctx, scope, grant.ChannelID)
			if err != nil {
				return api.Mail{}, err
			}
			return s.enqueueChannel(ctx, scope, from, grants, channel, request, report, artifacts)
		}
	} else if request.ChannelGrantID != "" {
		return api.Mail{}, problem(api.CodeForbidden, "human mail targets an agent life")
	}
	to, err := s.relatedLife(ctx, scope, request.RecipientLifeID)
	if err != nil {
		return api.Mail{}, err
	}
	targetGrants, err := s.relationGrants(ctx, scope, to)
	if err != nil {
		return api.Mail{}, err
	}
	if scope.Actor.Kind == "lane" {
		if report && from.ParentLifeID != to.LifeID {
			return api.Mail{}, problem(api.CodeForbidden, "reports follow the authentic direct starter")
		}
		if err := relation(relationFacts(from), to); err != nil {
			return api.Mail{}, err
		}
	}
	comparisons = append(comparisons,
		api.Compare{Kind: api.CompareLane, ID: to.LifeID, Generation: to.Generation},
		api.Compare{Kind: api.CompareGrants, ID: targetGrants.ID, Generation: targetGrants.Generation},
	)
	if _, err := s.content(ctx, scope, request.Content); err != nil {
		return api.Mail{}, err
	}
	if request.ReplyTo != "" {
		if err := s.reply(ctx, scope, request); err != nil {
			return api.Mail{}, err
		}
	}
	for _, artifact := range artifacts {
		if err := s.artifact(ctx, scope, artifact); err != nil {
			return api.Mail{}, err
		}
	}
	guards, err := s.proofGuard(ctx, scope)
	if err != nil {
		return api.Mail{}, err
	}
	if scope.Actor.Kind == "lane" {
		guards = append(guards, api.TransactionGuard{Cancellation: &api.CancellationCheck{LifeID: from.LifeID, Epoch: from.CancellationEpoch}})
	}
	mail := api.Mail{
		Generation: 1, Artifacts: append([]api.BlobRef{}, artifacts...),
		ID: derivedID("mail", scope), Sender: scope.Actor, RecipientLifeID: to.LifeID,
		ChannelGrantID: request.ChannelGrantID,
		Content:        request.Content, Source: scope.Source, Status: "queued", Ask: request.Ask, ReplyTo: request.ReplyTo,
	}
	subject := from
	if scope.Actor.Kind == "human" {
		var err error
		subject, err = s.lane(ctx, scope, api.LifeRef{LifeID: to.LifeID})
		if err != nil {
			return api.Mail{}, err
		}
		if subject.Generation != to.Generation {
			return api.Mail{}, problem(api.CodeConflict, "human mail target changed before enqueue")
		}
	}
	raw, err := json.Marshal(mail)
	if err != nil {
		return api.Mail{}, problem(api.CodeIntegrity, "cannot encode the mail intent")
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	operationID, effectID := derivedID("operation", scope), derivedID("delivery", scope)
	makeEvent := func(kind api.EventKind, id api.ID) api.Event {
		return api.Event{
			Schema: api.SchemaVersion, ID: id, Config: scope.Config, Kind: kind,
			Actor: scope.Actor, RequestedBy: scope.Actor, RequestID: scope.Request.RequestID, OperationID: operationID,
			LifeID: subject.LifeID, Run: subject.Run, ParentLifeID: subject.ParentLifeID, RootLifeID: subject.RootLifeID,
			StarterChain: append([]api.ID{}, subject.StarterChain...), StarterEventSeq: subject.StarterEventSeq,
			RequestedAt: now, ObservedAt: now, Origin: "service", Payload: raw,
		}
	}
	events := []api.Event{makeEvent("mail.queued", derivedID("queued", scope))}
	if report {
		events = append(events, makeEvent("report.submitted", derivedID("report", scope)))
	}
	intent := api.InternalIntent{ID: derivedID("intent", scope), Kind: api.InternalMailDeliver,
		Config: scope.Config, Actor: api.Actor{Kind: "service", ID: "mail-delivery"}, RequestedBy: scope.Actor,
		CauseOperationID: operationID, CauseRequestID: scope.Request.RequestID, EffectID: effectID,
		Target: api.LifeRef{LifeID: to.LifeID}}
	var exact []byte
	if scope.Frame != nil {
		exact = append([]byte(nil), scope.Frame.Bytes()...)
	} else {
		exact, err = json.Marshal(scope.Request)
		if err != nil {
			return api.Mail{}, problem(api.CodeIntegrity, "cannot retain the typed request")
		}
	}
	commit, err := s.deps.Store.Transact(ctx, api.Transaction{
		Scope: scope, Compare: comparisons, Events: events, RawRequest: exact,
		Reply: &api.RPCReply{Result: raw}, Guards: guards, Writes: api.StateWrites{Mail: []api.Mail{mail}},
		Effects: []api.Effect{{ID: effectID, OperationID: operationID, Context: &intent, Deliver: &mail}},
	})
	if err != nil {
		return api.Mail{}, err
	}
	if commit.Operation.Error != nil {
		return api.Mail{}, commit.Operation.Error
	}
	switch commit.Operation.Status {
	case "pending", "running", "succeeded":
	default:
		return api.Mail{}, problem(api.CodeIntegrity, "store returned a failed or unknown mail operation without its error")
	}
	if !validID(commit.Operation.ID) || commit.FirstSeq == 0 || commit.LastSeq < commit.FirstSeq || commit.LastSeq > maxExact {
		return api.Mail{}, problem(api.CodeIntegrity, "store returned an invalid mail commit receipt")
	}
	// The exact durable reply is stamped atomically with the projection, events
	// and outbox. A later mailbox read can no longer reconstruct this receipt.
	kept, err := committedMail(commit.Reply)
	if err != nil {
		return api.Mail{}, err
	}
	mail.QueuedSeq = kept.QueuedSeq
	if !reflect.DeepEqual(kept, mail) || kept.QueuedSeq < commit.FirstSeq || kept.QueuedSeq > commit.LastSeq {
		return api.Mail{}, problem(api.CodeIntegrity, "committed mail differs from the screened intent")
	}
	return kept, nil
}

func committedMail(reply *api.RPCReply) (api.Mail, error) {
	if reply == nil || (reply.Error == nil) == (len(reply.Result) == 0) {
		return api.Mail{}, problem(api.CodeIntegrity, "mail commit omitted its exact typed reply")
	}
	if reply.Error != nil {
		return api.Mail{}, reply.Error
	}
	return DecodeMailResult(reply.Result)
}

func (s *Service) replayMail(ctx context.Context, scope api.Scope) (api.Mail, bool, error) {
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if errorCode(err, api.CodeNotFound) {
		return api.Mail{}, false, nil
	}
	if err != nil {
		return api.Mail{}, false, err
	}
	if err := validReplay(scope, key, receipt); err != nil {
		return api.Mail{}, false, err
	}
	if receipt.Reply == nil {
		// The winning dispatcher invocation must perform this preflight; waiting
		// on its own pending receipt would prevent the original queue commit.
		// Matching IDs/frames do not grant ownership to another invocation.
		if dispatch, ok := s.deps.Store.(interface {
			OwnsMutation(context.Context, api.Scope, api.RequestKey, api.ID) (bool, error)
		}); ok {
			owned, err := dispatch.OwnsMutation(ctx, scope, key, receipt.Operation.ID)
			if err != nil {
				return api.Mail{}, false, err
			}
			if owned {
				return api.Mail{}, false, nil
			}
		}
		receipt, err = s.deps.Store.AwaitReceipt(ctx, scope, key)
		if err != nil {
			return api.Mail{}, false, err
		}
	}
	if err := validReplay(scope, key, receipt); err != nil {
		return api.Mail{}, false, err
	}
	mail, err := committedMail(receipt.Reply)
	if err == nil && mail.ID != derivedID("mail", scope) {
		return api.Mail{}, false, problem(api.CodeIntegrity, "mail replay receipt has a different immutable identity")
	}
	return mail, true, err
}

func validReplay(scope api.Scope, key api.RequestKey, receipt api.MutationReceipt) error {
	if receipt.Config != scope.Config || receipt.Key != key || receipt.Actor != scope.Actor {
		return problem(api.CodeIntegrity, "mail replay receipt has different request authority")
	}
	return nil
}

func (s *Service) content(ctx context.Context, scope api.Scope, ref api.BlobRef) (result []byte, resultErr error) {
	if err := validContent(ref); err != nil {
		return nil, err
	}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	if err := s.objectMetadata(ctx, scope, ref); err != nil {
		return nil, err
	}
	limit := int(ref.Bytes) + 1
	if limit > api.MaxChunkBytes {
		limit = api.MaxChunkBytes
	}
	chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Limit: limit})
	if err != nil {
		return nil, err
	}
	if chunk.ObjectID != ref.ID || chunk.Offset != 0 || int64(len(chunk.Data)) != ref.Bytes || hashBytes(chunk.Data) != chunk.SHA256 || hashBytes(chunk.Data) != ref.SHA256 {
		return nil, problem(api.CodeIntegrity, "mail bytes differ from the committed blob reference")
	}
	if ref.Bytes == api.MaxChunkBytes {
		tail, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: ref.Bytes, Limit: 1})
		if err != nil {
			return nil, err
		}
		if tail.ObjectID != ref.ID || tail.Offset != ref.Bytes || len(tail.Data) != 0 || hashBytes(tail.Data) != tail.SHA256 {
			return nil, problem(api.CodeIntegrity, "mail blob exceeds its declared length")
		}
	}
	if err := CheckContent(chunk.Data); err != nil {
		return nil, err
	}
	return chunk.Data, nil
}

func hashBytes(data []byte) api.Digest {
	digest := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(digest[:]))
}

func (s *Service) findMail(ctx context.Context, scope api.Scope, target, id api.ID) (api.Mail, error) {
	mailbox := target
	if scope.Actor.Kind == "lane" {
		mailbox = scope.Actor.LifeID
	}
	request := api.ListRequest{LifeID: mailbox, Limit: 200}
	seen := make(map[string]bool)
	for {
		if err := ctx.Err(); err != nil {
			return api.Mail{}, cancelled(err)
		}
		page, err := s.deps.Store.Mail(ctx, scope, request)
		if err != nil {
			return api.Mail{}, err
		}
		if len(page.Messages) > request.Limit {
			return api.Mail{}, problem(api.CodeIntegrity, "store exceeded the mailbox page bound")
		}
		for _, mail := range page.Messages {
			if err := validStoredMail(mail); err != nil {
				return api.Mail{}, err
			}
			if scope.Actor.Kind == "lane" && mail.Sender.LifeID != scope.Actor.LifeID && mail.RecipientLifeID != scope.Actor.LifeID {
				return api.Mail{}, problem(api.CodeIntegrity, "store exposed mail outside its participant ACL")
			}
			if mail.ID == id {
				return mail, nil
			}
		}
		if page.Cursor == "" {
			return api.Mail{}, problem(api.CodeNotFound, "the mail object is absent or not visible")
		}
		if len(page.Cursor) > maxCursor || seen[page.Cursor] {
			return api.Mail{}, problem(api.CodeIntegrity, "store returned an invalid or repeated mailbox cursor")
		}
		seen[page.Cursor], request.Cursor = true, page.Cursor
	}
}

func (s *Service) reply(ctx context.Context, scope api.Scope, request api.MailSendRequest) error {
	prior, err := s.findMail(ctx, scope, request.RecipientLifeID, request.ReplyTo)
	if err != nil {
		return err
	}
	if scope.Actor.Kind == "lane" {
		if request.ChannelGrantID != "" {
			if prior.RecipientLifeID != scope.Actor.LifeID || prior.Sender.Kind != "human" {
				return problem(api.CodeForbidden, "channel reply must refer to human mail addressed to this life")
			}
			return nil
		}
		if prior.RecipientLifeID != scope.Actor.LifeID || prior.Sender.Kind != "lane" || prior.Sender.LifeID != request.RecipientLifeID {
			return problem(api.CodeForbidden, "reply linkage must refer to mail from this destination to the sender")
		}
	} else if prior.Sender.Kind != "lane" || prior.Sender.LifeID != request.RecipientLifeID {
		return problem(api.CodeForbidden, "human reply linkage must refer to a visible report from the target life")
	}
	return nil
}
