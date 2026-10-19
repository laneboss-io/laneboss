package api

import "context"

// RuntimeServices closes the service's outbox/recovery/scheduler dependencies.
// These are service-only interfaces, never request-supplied objects or RPCs.
type RuntimeServices struct {
	Credentials        CredentialProjectionBroker
	CredentialIdentity CredentialProjectionIdentity
	Store              StateStore
	Helper             HelperControl
	Publisher          OrgPublisher
	Delivery           MailDelivery
	Deployment         DeploymentCoordinator
	Intake             OwnerIntake
	Config             string
	ArtifactSHA256     Digest
	Socket             string
	Lifecycle          LifecycleAPI
	LaunchPlanner      LaunchPlanner
	Continuation       Continuation
	Watchdog           Watchdog
	Identity           Authenticator
	Launcher           Launcher
	Worker             DataWorker
	Messaging          MessagingAPI
	Approval           ApprovalAPI
	Migration          MigrationAPI
	Packaging          PackagingAPI
}

// RuntimeBinder is implemented by the service transport before it may serve.
// Binding must fail if its effect reconciliation/scheduler cannot use these
// dependencies. Merely constructing a watchdog never enables continuation.
type RuntimeBinder interface {
	BindRuntime(context.Context, RuntimeServices) error
}

// ServiceHost owns installed listener ACLs and all connection lifetimes. The
// composition root must not invent one broadly reachable socket or stale-path
// unlink recovery. Close drains connections/effects and closes the owned store.
type ServiceHost interface {
	RuntimeBinder
	ServeInstalled(context.Context) error
	Close() error
}

// WatchdogBinder breaks the lifecycle/continuation construction cycle while
// requiring stop/abandon/clean/revocation to cancel future quota continuation.
type WatchdogBinder interface {
	BindWatchdog(Watchdog) error
}
