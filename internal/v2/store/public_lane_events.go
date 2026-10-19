package store

import (
	"context"
	"encoding/json"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Public methods produce authoritative events inside their closed transaction
// catalog. The authenticated lane remains the requester; this is not raw-event
// authority and never changes an observation into a service principal.
func (s *Service) publicLaneEvents(ctx context.Context, db queryer, input api.Transaction) (bool, error) {
	if input.Scope.Actor.Kind != "lane" {
		return false, nil
	}
	if input.Reply != nil && input.Reply.Error != nil {
		return false, nil
	}
	method := input.Scope.Request.Method
	mail := method == "mail.send" || method == "report.submit"
	switch method {
	case "mail.send", "report.submit", "lane.stop", "lane.mark", "lane.review", "lane.loop", "lane.resume", "lane.turn", "lane.clean", "lane.archive", "lane.input", "policy.evaluate":
	default:
		return false, nil
	}
	var from api.Lane
	if err := storedProjection(ctx, db, "lane", input.Scope.Actor.LifeID, &from); err != nil {
		return false, err
	}
	if from.LaunchID != input.Scope.LaunchID || from.Level != input.Scope.Actor.Level || from.Role != input.Scope.Actor.Role || from.Cleaned || from.State == "merged" || from.State == "abandoned" {
		return false, fault(api.CodeForbidden, "public event requester no longer owns its current lane")
	}
	if err := s.mailGrantChain(ctx, db, from); err != nil {
		return false, err
	}
	subject := from
	if mail {
		if err := s.publicMailIntent(ctx, db, input, from); err != nil {
			return false, err
		}
	} else {
		var selector struct {
			Target        api.LifeRef `json:"target"`
			LogicalTurnID api.ID      `json:"logical_turn_id"`
		}
		if err := json.Unmarshal(input.Scope.Request.Params, &selector); err != nil || selector.Target.LifeID == "" || selector.Target.Run == 0 {
			return false, wire.Invalid("lifecycle event needs its exact authenticated target")
		}
		if err := storedProjection(ctx, db, "lane", selector.Target.LifeID, &subject); err != nil {
			return false, err
		}
		if subject.Run != selector.Target.Run || subject.Cleaned || !laneControls(from, subject) {
			return false, fault(api.CodeForbidden, "lifecycle event target is outside the authenticated starter tree")
		}
		if method == "policy.evaluate" && (subject.LifeID != from.LifeID || selector.LogicalTurnID != subject.LogicalTurnID) {
			return false, fault(api.CodeForbidden, "policy event differs from the authenticated current turn")
		}
		if method == "lane.review" && subject.LifeID == from.LifeID {
			return false, fault(api.CodeForbidden, "executor cannot review its own life")
		}
	}
	for _, event := range input.Events {
		if event.Origin != "service" || event.Actor != input.Scope.Actor || event.RequestedBy != input.Scope.Actor ||
			event.LifeID != subject.LifeID || event.Run != subject.Run || event.ParentLifeID != subject.ParentLifeID ||
			event.RootLifeID != subject.RootLifeID || event.StarterEventSeq != subject.StarterEventSeq || !slices.Equal(event.StarterChain, subject.StarterChain) {
			return false, fault(api.CodeForbidden, "public event differs from its authenticated requester and target lineage")
		}
	}
	return true, nil
}

func laneControls(from, to api.Lane) bool {
	if from.LifeID == to.LifeID {
		return true
	}
	index := slices.Index(to.StarterChain, from.LifeID)
	return from.RootLifeID == to.RootLifeID && from.Level > to.Level && index >= 0 && slices.Equal(to.StarterChain[:index], from.StarterChain)
}

func mailRelated(from, to api.Lane) bool {
	return from.LifeID != to.LifeID && (laneControls(from, to) ||
		from.RootLifeID == to.RootLifeID && from.ParentLifeID == to.LifeID && from.Level < to.Level &&
			len(from.StarterChain) > 0 && slices.Equal(from.StarterChain[:len(from.StarterChain)-1], to.StarterChain) ||
		from.RootLifeID == to.RootLifeID && from.Level == to.Level && from.ParentLifeID != "" && from.ParentLifeID == to.ParentLifeID && slices.Equal(from.StarterChain, to.StarterChain))
}

func (s *Service) mailGrantChain(ctx context.Context, db queryer, lane api.Lane) error {
	seen := map[api.ID]bool{}
	for {
		if lane.Cleaned || lane.State == "merged" || lane.State == "abandoned" {
			return fault(api.CodeForbidden, "mail authority has a retired starter")
		}
		if seen[lane.LifeID] || len(seen) > 4 {
			return fault(api.CodeIntegrity, "mail authority has cyclic ancestry")
		}
		seen[lane.LifeID] = true
		var grants api.GrantSet
		if err := storedProjection(ctx, db, "grants", lane.GrantSetID, &grants); err != nil {
			return err
		}
		if grants.LifeID != lane.LifeID || grants.ParentLifeID != lane.ParentLifeID || grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
			return fault(api.CodeForbidden, "public event grants are revoked, expired or foreign")
		}
		if lane.ParentLifeID == "" {
			return nil
		}
		var parent api.Lane
		if err := storedProjection(ctx, db, "lane", lane.ParentLifeID, &parent); err != nil {
			return err
		}
		lane = parent
	}
}

func (s *Service) publicMailIntent(ctx context.Context, db queryer, input api.Transaction, from api.Lane) error {
	if len(input.Writes.Mail) != 1 || len(input.Effects) != 1 {
		return fault(api.CodeForbidden, "lane mail requires its exact queued object and delivery effect")
	}
	mail := input.Writes.Mail[0]
	var requested api.MailSendRequest
	if input.Scope.Request.Method == "report.submit" {
		var report api.ReportRequest
		if err := wire.Decode(input.Scope.Request.Params, &report); err != nil {
			return err
		}
		requested = api.MailSendRequest{RecipientLifeID: from.ParentLifeID, ChannelGrantID: report.ChannelGrantID, Content: report.Content, Ask: report.Ask, ReplyTo: report.ReplyTo}
		if !slices.Equal(report.Artifacts, mail.Artifacts) {
			return fault(api.CodeForbidden, "report artifacts differ from the original request")
		}
	} else if err := wire.Decode(input.Scope.Request.Params, &requested); err != nil {
		return err
	}
	// Channel publication has its distinct staged job protocol. It cannot use
	// this lane-to-lane admission to bypass the protected worker enrollment.
	if requested.ChannelGrantID != "" || mail.ChannelGrantID != "" {
		return s.publicChannel(ctx, db, input, from, mail, requested)
	}
	if len(input.Writes.WorkerLeases) != 0 {
		return fault(api.CodeForbidden, "lane mail cannot publish unrelated worker leases")
	}
	if mail.Sender != input.Scope.Actor || mail.RecipientLifeID != requested.RecipientLifeID || mail.Content != requested.Content || mail.Ask != requested.Ask || mail.ReplyTo != requested.ReplyTo || mail.Source != input.Scope.Source || mail.Status != "queued" || mail.Generation != 1 || mail.QueuedSeq != 0 || mail.LogicalTurnID != "" || mail.Answer != nil {
		return fault(api.CodeForbidden, "queued mail differs from its authenticated public input")
	}
	var to api.Lane
	if err := storedProjection(ctx, db, "lane", mail.RecipientLifeID, &to); err != nil {
		return err
	}
	if to.Cleaned || to.State == "merged" || to.State == "abandoned" || !mailRelated(from, to) {
		return fault(api.CodeForbidden, "mail target has no current D7 relationship")
	}
	if err := s.mailGrantChain(ctx, db, to); err != nil {
		return err
	}
	expected := 1
	if input.Scope.Request.Method == "report.submit" {
		expected = 2
	}
	if len(input.Events) != expected {
		return fault(api.CodeForbidden, "mail transaction has an incomplete queue event shape")
	}
	for i, event := range input.Events {
		kind := api.EventKind("mail.queued")
		if i == 1 {
			kind = "report.submitted"
		}
		var payload api.Mail
		if event.Kind != kind || wire.Decode(event.Payload, &payload) != nil || !sameValue(payload, mail) {
			return fault(api.CodeForbidden, "mail journal differs from its queued object")
		}
	}
	effect := input.Effects[0]
	if effect.Deliver == nil || !sameValue(*effect.Deliver, mail) || effect.Context == nil || effect.Context.Kind != api.InternalMailDeliver || effect.Context.Target.LifeID != to.LifeID || effect.Context.Target.Run != 0 || effect.Context.LogicalTurnID != "" {
		return fault(api.CodeForbidden, "mail delivery effect differs from the actual queued recipient")
	}
	return nil
}
