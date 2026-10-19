// Package assembly is the composition root, owned exclusively by lb-v2-integrate.
package assembly

import (
	"context"
	"io"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/approval"
	"laneboss.io/laneboss/internal/v2/assembly/credn"
	"laneboss.io/laneboss/internal/v2/dashboard"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/distribution"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/guidance"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/judge"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/messaging"
	"laneboss.io/laneboss/internal/v2/migration"
	"laneboss.io/laneboss/internal/v2/policy"
	"laneboss.io/laneboss/internal/v2/records"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
	"laneboss.io/laneboss/internal/v2/runner/codex"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/service"
	"laneboss.io/laneboss/internal/v2/store"
	"laneboss.io/laneboss/internal/v2/templates"
	"laneboss.io/laneboss/internal/v2/watchdog"
)

type Options struct {
	Config           string
	BindingFile      string
	InstallationFile string
}

func Build(ctx context.Context, options Options) (*service.Server, error) {
	installation, err := loadInstallation(options)
	if err != nil {
		return nil, err
	}
	return build(ctx, installation)
}

func Serve(ctx context.Context, options Options) (resultErr error) {
	installation, err := loadInstallation(options)
	if err != nil {
		return err
	}
	server, err := build(ctx, installation)
	if err != nil {
		return err
	}
	host, ok := any(server).(api.ServiceHost)
	if !ok {
		return api.NotImplemented("lb-v2-service", "installed service host")
	}
	defer func() {
		// Close journals each owned cause before this fixed public refusal.
		closeErr := host.Close()
		if err := serveOutcome(ctx, closeErr); err != nil {
			resultErr = &api.Error{Code: api.CodeIntegrity, Message: "service shutdown could not close its owned resources", Instead: "Retain the service evidence and inspect connections, effects and the store before restarting."}
		}
	}()
	return serveOutcome(ctx, host.ServeInstalled(ctx))
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func build(ctx context.Context, installed Installation) (_ *service.Server, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, &api.Error{Code: api.CodeCancelled, Message: "service construction cancelled", Instead: "Inspect the installed service state before restarting."}
	}
	clock := wallClock{}
	cleanup := &helperCleanupNative{}
	credentialSource := credn.New()
	database, err := store.New(store.Dependencies{Config: installed.Config, Directory: installed.StateDirectory, Enrollment: installed.AdminEnrollment, Clock: clock, CleanupNative: cleanup, ArchiveNative: cleanup, CredentialProjection: credentialSource,
		JudgeMaxCostMicros: installed.PolicyMaxCostMicros, JudgeCost: func(config api.JudgeConfig, input, output int64) (int64, error) {
			provider := &installedJudge{provider: config.Provider, installation: installed}
			enrollment, err := provider.resolve(config)
			if err != nil {
				return 0, err
			}
			options, err := installedJudgeOptions(enrollment)
			if err != nil {
				return 0, err
			}
			return options.Cost(input, output)
		}})
	if err != nil {
		return nil, err
	}
	// store.New checks the full human inventory, including revoked software
	// credentials, under the shared production/E2E presence policy before return.
	state := &ownedState{Service: database, closers: ownedClosers{store: database}}
	defer func() {
		if resultErr != nil {
			if closer, ok := any(state).(io.Closer); ok {
				if err := closer.Close(); err != nil {
					resultErr = &api.Error{Code: api.CodeIntegrity, Message: "failed service construction could not close its store", Instead: "Preserve state and inspect the service-owned store before restarting."}
				}
			}
		}
	}()
	helper, err := admin.New(admin.Dependencies{Store: state, ServiceUID: installed.ServiceUID,
		Config: installed.Config, ArtifactSHA256: installed.ArtifactSHA256,
		RuntimeManifest: installed.RuntimeManifest, LaunchEnrollment: installed.LaunchEnrollment,
		Version: release.Version, Protocol: api.Protocol, Schema: api.SchemaVersion})
	if err != nil {
		return nil, err
	}
	if err := cleanup.bind(helper); err != nil {
		return nil, err
	}
	if err := credentialSource.BindNative(helper); err != nil {
		return nil, err
	}
	peers, err := platformPeers(helper)
	if err != nil {
		return nil, err
	}
	peers = installedCredentialPeers(peers, helper, installed)
	var sessionReads identity.SessionReadback
	if reader, ok := any(state).(identity.SessionReadback); ok {
		sessionReads = reader
	}
	identities, err := identity.New(identity.Dependencies{Peers: peers, Registry: helper, Store: state, Clock: clock, Sessions: sessionReads, Workers: helper})
	if err != nil {
		return nil, err
	}
	core, err := service.New(service.Dependencies{Binding: installed.Binding, Store: state, Authenticator: identities, Enrollment: identities, Clock: clock, IsolationEvidence: helper})
	if err != nil {
		return nil, err
	}
	server, err := service.NewServer(service.Options{Config: installed.Config, BindingFile: installed.BindingFile, AdminEnrollment: installed.AdminEnrollment},
		service.Dependencies{Binding: installed.Binding, Store: state, Authenticator: identities, Enrollment: identities, Clock: clock, IsolationEvidence: helper})
	if err != nil {
		return nil, err
	}
	if err := identities.BindConnections(server); err != nil {
		return nil, err
	}
	if err := helper.BindEnrollment(server); err != nil {
		return nil, err
	}
	launcher, err := platformLauncher(helper, installed.RuntimeManifest, installed.Binding.Backend, server)
	if err != nil {
		return nil, err
	}
	projectedLauncher := &projectionLauncher{Launcher: launcher, binder: helper}
	launcher = projectedLauncher
	if err := helper.BindIsolationProbe(launcher); err != nil {
		return nil, err
	}
	worker, err := dataworker.New(dataworker.Dependencies{Config: installed.Config, Controls: server, Launcher: launcher, Store: state, Helper: helper, Clock: clock})
	if err != nil {
		return nil, err
	}
	if err := credentialSource.BindWorkers(worker); err != nil {
		return nil, err
	}
	// The native secret backend comes first: grants resolves root enrolled profiles from it (grants G3).
	backend, err := installedSecrets(ctx, installed, clock)
	if err != nil {
		return nil, err
	}
	state.closers.resources = append(state.closers.resources, backend)
	delegation, err := grants.New(grants.Dependencies{Config: installed.Config, Human: identities, Store: state, Worker: worker, Clock: clock, Profiles: backend, Network: helper.ValidateNetworkGrant})
	if err != nil {
		return nil, err
	}
	usageScope, err := server.UsageServiceScope()
	if err != nil {
		return nil, err
	}
	credentials, err := secrets.New(secrets.Dependencies{Backend: backend, Store: state, ServiceScope: usageScope,
		Config: installed.Config, Grants: usageGrantResolver{GrantResolver: delegation, state: state, config: installed.Config}, Human: identities, Clock: clock,
		CodexValidator: codex.CredentialValidator{}, HeadlessValidator: claudock.CredentialValidator{}, APIKeyValidator: claudock.APIKeyValidator{},
		Helper: helper, CleanupNative: helper, WithdrawalNative: helper, Control: server, Bootstrap: server.UsageBootstrap(), UsageJobs: server, ProjectionIdentity: identities})
	if err != nil {
		return nil, err
	}
	if err := server.BindUsageSource(credentials); err != nil {
		return nil, err
	}
	if err := bindInitialProfiles(server, installed, credentials); err != nil {
		return nil, err
	}
	judgeWorker, err := bindNativeJudge(server, helper, installed)
	if err != nil {
		return nil, err
	}
	judgments, err := judge.New(judge.Dependencies{
		Clef:     &installedJudge{provider: api.DefaultJudgeProvider, installation: installed, worker: judgeWorker},
		TypeSafe: &installedJudge{provider: "typesafe", installation: installed, worker: judgeWorker},
		Store:    state, Clock: clock})
	if err != nil {
		return nil, err
	}
	var briefings *templates.Service
	policyJudge, policyCost, err := dashboardPolicySource(installed, judgments)
	if err != nil {
		return nil, err
	}
	rules, err := policy.NewInstalled(policy.Dependencies{Store: state, Judge: policyJudge, Clock: clock,
		MaxCostMicros:     policyCost,
		CommandDeadlineMS: installed.Judge.CommandDeadlineMS,
		ValidateSources: func(ctx context.Context, scope api.Scope, request api.OrgValidateRequest) (api.OrgValidation, error) {
			if briefings == nil {
				return api.OrgValidation{}, api.NotImplemented("lb-v2-templates", "installed source validator binding")
			}
			return briefings.ValidateSources(ctx, scope, request)
		}})
	if err != nil {
		return nil, err
	}
	reminders, err := guidance.New(guidance.Dependencies{Store: state, Judge: judgments, Clock: clock, MaxCostMicros: installed.PolicyMaxCostMicros})
	if err != nil {
		return nil, err
	}
	briefings, err = templates.New(templates.Dependencies{Store: state, Policy: rules, Publisher: worker, Clock: clock})
	if err != nil {
		return nil, err
	}
	runnerPorts := runnerDependencies{
		Store: state, Clock: clock, Sources: helper, Storage: helper, Grants: delegation,
		Credentials: credentials, UsageWindows: credentials, Materialization: server, Capture: helper}
	claudeDriver, codexDriver, err := installedRunners(installed, runnerPorts)
	if err != nil {
		return nil, err
	}
	// Runtime enrollment is a per-run gate. The stable service graph may start
	// without a vendor profile, but a runner plan cannot proceed until the
	// protected enrollment reference and exact life/home/slot pins are present.
	if closer, ok := claudeDriver.(io.Closer); ok {
		state.closers.resources = append(state.closers.resources, closer)
	}
	claudeDriver = guardRunnerEnrollment(claudeDriver, installed, api.DriverClaudock, runnerPorts)
	codexDriver = guardRunnerEnrollment(codexDriver, installed, api.DriverCodex, runnerPorts)
	lanes, err := lifecycle.New(lifecycle.Dependencies{Store: state, Identity: identities, Dispatch: server,
		Grants: delegation, Launcher: launcher, Sources: helper, Capture: helper, Claudock: claudeDriver, Codex: codexDriver,
		Credentials: credentials, Guidance: reminders, Templates: briefings, Blobs: core, Worker: worker, Review: worker, ReviewControl: server, Clock: clock})
	if err != nil {
		return nil, err
	}
	quota, err := watchdog.New(watchdog.Dependencies{Config: installed.Config, Claudock: claudeDriver, Grants: delegation, Store: state, Credentials: credentials, Lifecycle: lanes, Launcher: launcher, Clock: clock,
		ResolveUsage: credentials.ReadUsageProvenance})
	if err != nil {
		return nil, err
	}
	watchdogTarget, ok := any(lanes).(api.WatchdogBinder)
	if !ok {
		return nil, api.NotImplemented("lb-v2-lifecycle", "lifecycle.BindWatchdog")
	}
	if err := watchdogTarget.BindWatchdog(quota); err != nil {
		return nil, err
	}
	mail, err := messaging.New(messaging.Dependencies{Store: state, Clock: clock, Launcher: launcher, Credentials: credentials, Worker: worker, Preparer: server})
	if err != nil {
		return nil, err
	}
	changes, err := approval.New(approval.Dependencies{Store: state, Human: identities, Worker: worker, Publisher: worker, Clock: clock})
	if err != nil {
		return nil, err
	}
	views, err := dashboard.New(dashboard.Dependencies{Transport: server, Store: state, Human: identities,
		Identity: identities, Authenticator: identities, Lifecycle: lanes, Messaging: mail, Approval: changes})
	if err != nil {
		return nil, err
	}
	if installed.AdminEnrollment != nil {
		if err := views.ConfigureEnrollment(*installed.AdminEnrollment, server); err != nil {
			return nil, err
		}
	}
	data, err := records.New(records.Dependencies{Store: state, Worker: worker, Clock: clock})
	if err != nil {
		return nil, err
	}
	imports, err := migration.New(migration.Dependencies{Store: state, Human: identities, Worker: worker})
	if err != nil {
		return nil, err
	}
	releases, err := distribution.New(distribution.Dependencies{Store: state, Human: identities, Helper: helper, Control: server, Installer: helper, Migration: imports})
	if err != nil {
		return nil, err
	}
	runtimeTarget, ok := any(server).(api.ServiceHost)
	if !ok {
		return nil, api.NotImplemented("lb-v2-service", "installed service host")
	}
	if err := projectedLauncher.bindRuntime(ctx, runtimeTarget, api.RuntimeServices{Store: state, Helper: helper, Credentials: credentials, CredentialIdentity: identities, Publisher: worker, Delivery: mail, Deployment: releases, Intake: data, Config: installed.Config,
		ArtifactSHA256: installed.ArtifactSHA256, Socket: installed.Socket, Lifecycle: lanes, LaunchPlanner: lanes, Continuation: lanes,
		Watchdog: quota, Identity: identities, Launcher: launcher, Worker: worker, Messaging: mail,
		Approval: changes, Migration: imports, Packaging: releases}); err != nil {
		return nil, err
	}
	modules := []ownedModule{
		{"lb-v2-service", core}, {"lb-v2-identity", identities}, {"lb-v2-admin", helper},
		{"lb-v2-grants", delegation}, {"lb-v2-secrets", credentials}, {"lb-v2-judge", judgments},
		{"lb-v2-policy", rules}, {"lb-v2-guidance", reminders}, {"lb-v2-templates", briefings},
		{"lb-v2-lifecycle", lanes}, {"lb-v2-messaging", mail}, {"lb-v2-approval", changes},
		{"lb-v2-dashboard", views}, {"lb-v2-integrate", data}, {"lb-v2-migration", imports},
		{"lb-v2-packaging", releases},
	}
	if err := registerModules(server, modules); err != nil {
		return nil, err
	}
	if err := server.BindDashboard(views); err != nil {
		return nil, err
	}
	dashboardEntry, err := bindDashboardEntry(ctx, server, views, installed)
	if err != nil {
		return nil, err
	}
	state.closers.resources = append(state.closers.resources, dashboardEntry)
	credentialOwners, err := startInstalledCredentialOwners(ctx, installed, helper, identities, state, delegation, server)
	if err != nil {
		return nil, err
	}
	state.closers.resources = append(state.closers.resources, credentialOwners)
	return server, nil
}
