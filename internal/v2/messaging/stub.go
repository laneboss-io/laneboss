// Package messaging implements life-scoped mail and the direct report line.
// It never opens client paths or executes message content.
package messaging

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	Store api.StateStore
	Clock api.Clock
	// Fixed leased channel worker (draft.4 fix 10). A nil worker keeps channel
	// delivery a typed prerequisite; it never substitutes a local sender.
	Worker   api.ChannelWorker
	Preparer api.ChannelJobStore
	// Optional component-test adapters. Production authority is resolved from
	// the bound connection and the canonical StateStore when these are nil.
	Authenticator api.Authenticator
	Grants        api.GrantResolver
	Human         api.HumanVerifier
	Launcher      api.Launcher
	Credentials   api.CredentialBroker
}

type Service struct {
	deps Dependencies
}

func New(deps Dependencies) (*Service, error) {
	if deps.Store == nil || deps.Clock == nil {
		return nil, problem(api.CodePrerequisite, "messaging requires store and clock")
	}
	return &Service{deps: deps}, nil
}

var _ api.MessagingAPI = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func (s *Service) Register(registry api.Registrar) error {
	if registry == nil {
		return problem(api.CodePrerequisite, "messaging requires a registrar")
	}
	if err := registry.Register("mail.send", func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		request, err := DecodeMailSend(raw)
		if err != nil {
			return nil, err
		}
		result, err := s.MailSend(ctx, scope, request)
		return encodeResult(result, err)
	}); err != nil {
		return err
	}
	if err := registry.Register("mail.list", func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		request, err := DecodeMailList(raw)
		if err != nil {
			return nil, err
		}
		result, err := s.MailList(ctx, scope, request)
		return encodeResult(result, err)
	}); err != nil {
		return err
	}
	return registry.Register("report.submit", func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		request, err := DecodeReport(raw)
		if err != nil {
			return nil, err
		}
		result, err := s.ReportSubmit(ctx, scope, request)
		return encodeResult(result, err)
	})
}

func (s *Service) MailSend(ctx context.Context, scope api.Scope, request api.MailSendRequest) (api.Mail, error) {
	if err := validSend(request); err != nil {
		return api.Mail{}, err
	}
	if err := s.authorize(ctx, scope, "mail.send", request); err != nil {
		return api.Mail{}, err
	}
	return s.enqueue(ctx, scope, request, false, []api.BlobRef{})
}

func (s *Service) MailList(ctx context.Context, scope api.Scope, request api.ListRequest) (api.MailPage, error) {
	if err := validList(request); err != nil {
		return api.MailPage{}, err
	}
	if scope.Actor.Kind == "human" && scope.Connection != nil {
		var err error
		scope, err = api.WithReadAuthority(ctx, scope)
		if err != nil {
			return api.MailPage{}, err
		}
	}
	if err := s.authorize(ctx, scope, "mail.list", request); err != nil {
		return api.MailPage{}, err
	}
	if scope.Actor.Kind == "lane" {
		if request.LifeID != "" && request.LifeID != scope.Actor.LifeID {
			return api.MailPage{}, problem(api.CodeForbidden, "private mail is visible only to its participants")
		}
		request.LifeID = scope.Actor.LifeID
		if _, err := s.currentSender(ctx, scope); err != nil {
			return api.MailPage{}, err
		}
	}
	page, err := s.deps.Store.Mail(ctx, scope, request)
	if err != nil {
		return api.MailPage{}, err
	}
	if len(page.Messages) > request.Limit {
		return api.MailPage{}, problem(api.CodeIntegrity, "store exceeded the mailbox page bound")
	}
	seen := make(map[api.ID]bool)
	var previous api.Sequence
	for _, mail := range page.Messages {
		if err := validStoredMail(mail); err != nil {
			return api.MailPage{}, err
		}
		if seen[mail.ID] || mail.QueuedSeq <= previous {
			return api.MailPage{}, problem(api.CodeIntegrity, "store returned unordered or duplicate mail")
		}
		seen[mail.ID], previous = true, mail.QueuedSeq
		if request.LifeID != "" && mail.Sender.LifeID != request.LifeID && mail.RecipientLifeID != request.LifeID {
			return api.MailPage{}, problem(api.CodeIntegrity, "store returned mail outside the requested life filter")
		}
		if scope.Actor.Kind == "lane" && mail.Sender.LifeID != scope.Actor.LifeID && mail.RecipientLifeID != scope.Actor.LifeID {
			return api.MailPage{}, problem(api.CodeIntegrity, "store returned private mail outside the caller's mailbox")
		}
	}
	if page.Messages == nil {
		page.Messages = []api.Mail{}
	}
	return page, nil
}

func (s *Service) ReportSubmit(ctx context.Context, scope api.Scope, request api.ReportRequest) (api.Mail, error) {
	if err := validReport(request); err != nil {
		return api.Mail{}, err
	}
	if err := s.authorize(ctx, scope, "report.submit", request); err != nil {
		return api.Mail{}, err
	}
	if scope.Actor.Kind != "lane" {
		return api.Mail{}, problem(api.CodeForbidden, "only an authenticated lane has a report line")
	}
	from, err := s.currentSender(ctx, scope)
	if err != nil {
		return api.Mail{}, err
	}
	target := api.MailSendRequest{
		ChannelGrantID: request.ChannelGrantID, Content: request.Content, Ask: request.Ask, ReplyTo: request.ReplyTo,
	}
	if target.ChannelGrantID == "" {
		target.RecipientLifeID = from.ParentLifeID
		if target.RecipientLifeID == "" {
			return api.Mail{}, problem(api.CodeForbidden, "a root report requires an explicit current human channel grant")
		}
	}
	return s.enqueue(ctx, scope, target, true, request.Artifacts)
}

func encodeResult(value any, err error) (json.RawMessage, error) {
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, problem(api.CodeIntegrity, "cannot encode the messaging result")
	}
	return raw, nil
}
