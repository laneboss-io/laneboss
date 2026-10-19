// Package typesafe is owned by lb-v2-judge.
package typesafe

import (
	"context"
	"net/http"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

type Dependencies struct {
	Endpoint         string
	CredentialHandle api.ID
	Config           api.JudgeConfig
	Credential       api.SecretMaterial `json:"-"`
	Client           *http.Client       `json:"-"`
	Fit              wire.FitCheck      `json:"-"`
	SafetyTokens     int
	Retain           wire.Retain `json:"-"`
	Cost             wire.Cost   `json:"-"`
	ReserveMicros    int64
}

type Service struct {
	adapter *wire.Adapter
}

func (Dependencies) String() string   { return "TypeSafe dependencies (redacted)" }
func (Dependencies) GoString() string { return "TypeSafe dependencies (redacted)" }
func (Service) String() string        { return "TypeSafe service (redacted)" }
func (Service) GoString() string      { return "TypeSafe service (redacted)" }

func New(deps Dependencies) (*Service, error) {
	if deps.Config.Provider != "typesafe" {
		return nil, &api.Error{Code: api.CodeInvalid,
			Message: "TypeSafe requires the typesafe provider", Owner: "lb-v2-judge"}
	}
	adapter, err := wire.New(wire.Options{Endpoint: deps.Endpoint, Config: deps.Config,
		CredentialHandle: deps.CredentialHandle, Credential: deps.Credential,
		Client: deps.Client, Fit: deps.Fit, SafetyTokens: deps.SafetyTokens,
		Retain: deps.Retain, Cost: deps.Cost, ReserveMicros: deps.ReserveMicros})
	if err != nil {
		return nil, err
	}
	return &Service{adapter: adapter}, nil
}

var _ api.Judge = (*Service)(nil)

func (s *Service) Fit(ctx context.Context, request api.JudgeRequest) (api.TokenFit, error) {
	return s.adapter.Fit(ctx, request)
}

func (s *Service) Evaluate(ctx context.Context, request api.JudgeRequest) (api.JudgeReply, error) {
	return s.adapter.Evaluate(ctx, request)
}
