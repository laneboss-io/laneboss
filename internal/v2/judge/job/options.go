package job

import (
	"bytes"
	"context"
	"io"
	"math/big"
	"os/exec"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

type fitOutput struct{ bytes.Buffer }

func (b *fitOutput) Write(raw []byte) (int, error) {
	if b.Len()+len(raw) > 16384 {
		return 0, io.ErrShortBuffer
	}
	return b.Buffer.Write(raw)
}

func Options(setup Setup) wire.Options {
	return wire.Options{Endpoint: setup.Endpoint, Config: setup.Config,
		CredentialHandle: setup.CredentialHandle, Credential: api.SecretMaterial{Bytes: setup.Credential},
		SafetyTokens: setup.SafetyTokens, ReserveMicros: setup.ReserveMicros,
		Cost: func(input, output int64) (int64, error) {
			if input < 0 || output < 0 || setup.InputMicrosPerMillion < 0 || setup.OutputMicrosPerMillion < 0 {
				return 0, &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-judge", Message: "negative measured judge usage or enrolled price"}
			}
			amount := new(big.Int).Mul(big.NewInt(input), big.NewInt(setup.InputMicrosPerMillion))
			amount.Add(amount, new(big.Int).Mul(big.NewInt(output), big.NewInt(setup.OutputMicrosPerMillion)))
			amount.Add(amount, big.NewInt(999999))
			amount.Div(amount, big.NewInt(1000000))
			if !amount.IsInt64() || amount.Int64() > 1<<53-1 {
				return 0, &api.Error{Code: api.CodeBudget, Owner: "lb-v2-judge", Message: "measured judge price overflow"}
			}
			return amount.Int64(), nil
		},
		Fit: func(ctx context.Context, body []byte) (api.TokenFit, error) {
			command := exec.CommandContext(ctx, setup.TokenizerPath, setup.TokenizerArgs...)
			command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "GOMAXPROCS=1"}
			command.Stdin, command.Stderr = bytes.NewReader(body), io.Discard
			command.WaitDelay = 100 * time.Millisecond
			var output fitOutput
			command.Stdout = &output
			if command.Run() != nil {
				return api.TokenFit{}, &api.Error{Code: api.CodeUnscored, Owner: "lb-v2-judge", Message: "installed serving tokenizer failed"}
			}
			var fit api.TokenFit
			if api.DecodeObject(output.Bytes(), &fit) != nil || !fit.Proved || fit.InputBytes != len(body) || fit.InputTokens < 1 ||
				fit.ContextTokens != setup.Config.ContextTokens || fit.TokenizerSHA256 != setup.Config.TokenizerSHA256 {
				return api.TokenFit{}, &api.Error{Code: api.CodeUnscored, Owner: "lb-v2-judge", Message: "installed tokenizer proof differs from complete bytes or deployment"}
			}
			return fit, nil
		}}
}
