// Package clef is owned by lb-v2-judge.
package clef

import (
	"context"
	"net/http"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

type Dependencies struct {
	Endpoint string
	Config   api.JudgeConfig
	// The outside worker supplies material from its protected credential slot.
	// No provider credential file or environment variable is opened here.
	CredentialHandle api.ID
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

func (Dependencies) String() string   { return "Clef dependencies (redacted)" }
func (Dependencies) GoString() string { return "Clef dependencies (redacted)" }
func (Service) String() string        { return "Clef service (redacted)" }
func (Service) GoString() string      { return "Clef service (redacted)" }

func New(deps Dependencies) (*Service, error) {
	resolved, err := api.ResolveJudgeConfig(deps.Config)
	if err != nil {
		return nil, err
	}
	deps.Config = resolved
	if deps.Config.Provider != "clef-sglang" {
		return nil, &api.Error{Code: api.CodeInvalid,
			Message: "Clef requires the clef-sglang provider", Owner: "lb-v2-judge"}
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
