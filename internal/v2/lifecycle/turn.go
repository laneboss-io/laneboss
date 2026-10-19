package lifecycle

import "laneboss.io/laneboss/internal/v2/api"

// turnTrigger validates the request's ordered references without taking any
// authority from a mail sender. The caller's Scope remains the requester;
// trusted delivery still has to resolve/revalidate senders and causing seqs.
func turnTrigger(request api.TurnRequest) (api.Trigger, error) {
	if request.MailIDs == nil || len(request.MailIDs) > 200 ||
		len(request.MailIDs) == 0 && request.IdleMessage == nil {
		return api.Trigger{}, invalid("turn requires ordered mail or an idle message")
	}
	seen := make(map[api.ID]bool, len(request.MailIDs))
	for _, id := range request.MailIDs {
		if !validID(id) || seen[id] {
			return api.Trigger{}, invalid("turn contains an invalid or repeated mail ID")
		}
		seen[id] = true
	}
	if request.IdleMessage != nil &&
		(!validBlob(*request.IdleMessage) || request.IdleMessage.Class != "task") {
		return api.Trigger{}, invalid("invalid idle message reference")
	}
	kind := "idle"
	if len(request.MailIDs) > 0 {
		kind = "mail"
	}
	return api.Trigger{Kind: kind, MailIDs: append([]api.ID{}, request.MailIDs...),
		CausingSeqs: []api.Sequence{}}, nil
}
