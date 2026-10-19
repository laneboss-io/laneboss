package assembly

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/clef"
	"laneboss.io/laneboss/internal/v2/judge/job"
	"laneboss.io/laneboss/internal/v2/judge/typesafe"
	"laneboss.io/laneboss/internal/v2/judge/wire"
	"laneboss.io/laneboss/internal/v2/service"
)

func judgeEnrollments(installed Installation) []JudgeInstallation {
	entries := []JudgeInstallation{{Config: installed.Judge, Endpoint: installed.JudgeEndpoint,
		CredentialHandle: installed.JudgeCredentialHandle, Worker: installed.JudgeWorker}}
	if installed.JudgeAlternative != nil {
		entries = append(entries, *installed.JudgeAlternative)
	}
	return entries
}

func bindNativeJudge(server *service.Server, helper *admin.Service, installed Installation) (api.JudgeWorker, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	raw, err := readProtected(filepath.Join(filepath.Dir(executable), "runtime", installed.Config, "manifest.json"), api.MaxObjectBytes)
	if err != nil {
		return nil, err
	}
	var runtime api.RuntimeManifest
	if json.Unmarshal(raw, &runtime) != nil || wire.Digest(raw) != installed.RuntimeManifest.SHA256 ||
		int64(len(raw)) != installed.RuntimeManifest.Bytes || runtime.Bootstrap.SHA256 != installed.ArtifactSHA256 {
		return nil, judgeWorkerPrerequisite("judge native runtime differs from the installed release")
	}
	return server.NewJudgeWorker(helper, installed.RuntimeManifest, runtime.Bootstrap, func(ctx context.Context, config api.JudgeConfig) (job.Setup, error) {
		selected := &installedJudge{provider: config.Provider, installation: installed}
		enrolled, err := selected.resolve(config)
		if err != nil {
			return job.Setup{}, err
		}
		options, err := installedJudgeOptions(enrolled)
		if err != nil {
			return job.Setup{}, err
		}
		priceRaw, err := readProtected(enrolled.Worker.PriceFile, 16384)
		if err != nil {
			return job.Setup{}, err
		}
		var price judgePrice
		if api.DecodeObject(priceRaw, &price) != nil || wire.Digest(priceRaw) != enrolled.Worker.PriceSHA256 {
			return job.Setup{}, judgeWorkerPrerequisite("judge native price changed")
		}
		tokenizer := ""
		for _, object := range runtime.Objects {
			if object.Content.SHA256 == enrolled.Worker.TokenizerExecutableSHA256 && object.Mode == 0555 {
				tokenizer = "/runtime/" + string(object.ID)
			}
		}
		if tokenizer == "" {
			return job.Setup{}, judgeWorkerPrerequisite("judge tokenizer is absent from its measured native runtime")
		}
		return job.Setup{Config: enrolled.Config, Endpoint: enrolled.Endpoint, CredentialHandle: enrolled.CredentialHandle,
			Credential: options.Credential.Bytes, TokenizerPath: tokenizer, TokenizerArgs: enrolled.Worker.TokenizerArgs,
			ProviderSocket: "/runtime/judge-provider.sock", SafetyTokens: options.SafetyTokens, ReserveMicros: options.ReserveMicros,
			InputMicrosPerMillion: price.InputMicrosPerMillion, OutputMicrosPerMillion: price.OutputMicrosPerMillion}, nil
	})
}

// Both adapters are wired, but construction is lazy and only follows the
// scoped judge's policy resolution. Missing enrollment is a prerequisite error,
// never permission to use whichever provider the boot file happens to list.
type installedJudge struct {
	provider     string
	installation Installation
	worker       api.JudgeWorker
}

var _ api.Judge = (*installedJudge)(nil)

func (p *installedJudge) resolve(config api.JudgeConfig) (JudgeInstallation, error) {
	approved, err := api.ResolveJudgeConfig(config)
	if err != nil {
		return JudgeInstallation{}, err
	}
	if approved.Provider == p.provider {
		for _, enrollment := range judgeEnrollments(p.installation) {
			pins, err := api.ResolveJudgeConfig(enrollment.Config)
			if err != nil {
				return JudgeInstallation{}, err
			}
			if approved.Provider == pins.Provider && approved.Model == pins.Model &&
				approved.DeploymentSHA256 == pins.DeploymentSHA256 && approved.TokenizerSHA256 == pins.TokenizerSHA256 && approved.ContextTokens == pins.ContextTokens {
				enrollment.Config = approved
				return enrollment, nil
			}
		}
	}
	return JudgeInstallation{}, &api.Error{Code: api.CodePrerequisite, Message: "approved judge has no matching enrolled deployment", Instead: "Enroll that approved provider/model/deployment; retain unavailable status without switching providers."}
}

func (p *installedJudge) adapter(config api.JudgeConfig) (api.Judge, error) {
	return p.adapterWithRetention(config, nil)
}

func (p *installedJudge) adapterWithRetention(config api.JudgeConfig, retain func(context.Context, string, []byte) (api.BlobRef, error)) (api.Judge, error) {
	enrollment, err := p.resolve(config)
	if err != nil {
		return nil, err
	}
	options, err := installedJudgeOptions(enrollment)
	if err != nil {
		return nil, err
	}
	if p.provider == api.DefaultJudgeProvider {
		return clef.New(clef.Dependencies{Endpoint: enrollment.Endpoint, Config: enrollment.Config,
			CredentialHandle: enrollment.CredentialHandle, Credential: options.Credential,
			Fit: options.Fit, SafetyTokens: options.SafetyTokens, ReserveMicros: options.ReserveMicros, Cost: options.Cost, Retain: retain})
	}
	return typesafe.New(typesafe.Dependencies{Endpoint: enrollment.Endpoint,
		CredentialHandle: enrollment.CredentialHandle, Credential: options.Credential, Config: enrollment.Config,
		Fit: options.Fit, SafetyTokens: options.SafetyTokens, ReserveMicros: options.ReserveMicros, Cost: options.Cost, Retain: retain})
}

func (p *installedJudge) Fit(ctx context.Context, request api.JudgeRequest) (api.TokenFit, error) {
	provider, err := p.adapter(request.Config)
	if err != nil {
		return api.TokenFit{}, err
	}
	return provider.Fit(ctx, request)
}

func (p *installedJudge) Evaluate(ctx context.Context, request api.JudgeRequest) (api.JudgeReply, error) {
	return api.JudgeReply{}, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-judge", Message: "judge provider requires its durable execution claim", Instead: "Dispatch through the scoped judge and its protected outside worker."}
}

func (p *installedJudge) ReadyForJudge(ctx context.Context, config api.JudgeConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.worker == nil {
		return judgeWorkerPrerequisite("installed judge requires its authenticated native worker job")
	}
	enrollment, err := p.resolve(config)
	if err != nil {
		return err
	}
	_, err = installedJudgeOptions(enrollment)
	return err
}

func (p *installedJudge) EvaluateLeased(ctx context.Context, execution api.JudgeExecution, retain func(context.Context, string, []byte) (api.BlobRef, error)) (api.JudgeReply, api.TokenFit, error) {
	if p.worker == nil {
		return api.JudgeReply{}, api.TokenFit{}, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-judge", Message: "installed judge requires its authenticated native worker job",
			Instead: "Bind the fixed outside worker to the original durable execution claim; retain unknown cost reservations until its measured result is reconciled."}
	}
	if _, err := p.resolve(execution.Request.Config); err != nil {
		return api.JudgeReply{}, api.TokenFit{}, err
	}
	return p.worker.EvaluateLeased(ctx, execution, retain)
}
