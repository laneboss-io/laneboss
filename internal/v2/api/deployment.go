package api

import "context"

type FreezeRequest struct {
	OperationID                    ID
	ExpectedInstallationGeneration Generation
	Reason                         BlobRef
}

type FreezeReceipt struct {
	ID                     ID
	Config                 string
	OperationID            ID
	InstallationGeneration Generation
	DispatchEpoch          Generation
	FrozenAt               Timestamp
}

type QuiescenceReceipt struct {
	ID                  ID
	Freeze              FreezeReceipt
	Observations        []ProcessObservation
	PendingEffectIDs    []ID
	PendingCaptureBytes int64
	ObservedAt          Timestamp
}

type FrozenBackup struct {
	ID               ID
	StateManifest    BlobRef
	ConfigManifest   BlobRef
	ReleaseManifest  BlobRef
	RecoveryEvidence BlobRef
	Quiescence       QuiescenceReceipt
	VerifiedAt       Timestamp
}

type DeploymentPlan struct {
	ID                     ID
	Public                 UpgradePlan
	Config                 string
	Actor                  Actor
	InstallationGeneration Generation
	EndpointGeneration     Generation
	Generation             Generation
	Phase                  string
	OldRelease             ReleaseManifest
	Backup                 *FrozenBackup
	Freeze                 *FreezeReceipt
	OperationID            ID
	MigrationPlanID        ID
}

type DeploymentReceipt struct {
	ID                     ID
	PlanID                 ID
	OperationID            ID
	InstallationGeneration Generation
	EndpointGeneration     Generation
	ArtifactSHA256         Digest
	BackupID               ID
	MigrationOperationID   ID
	ReadBack               BlobRef
	CompletedAt            Timestamp
}

type DeploymentInstallRequest struct {
	Lease  EffectLease
	Plan   DeploymentPlan
	Backup FrozenBackup
}

type RollbackRequest struct {
	Lease              EffectLease
	PlanID             ID
	Backup             FrozenBackup
	RetainedNewHistory BlobRef
}

type DispatchControl interface {
	FreezeDispatch(context.Context, Scope, FreezeRequest) (FreezeReceipt, error)
	DrainDispatch(context.Context, Scope, FreezeReceipt) (QuiescenceReceipt, error)
	ThawDispatch(context.Context, Scope, FreezeReceipt) error
}

// DeploymentInstaller is administrator-bound, separate from lane UID leases.
// It stages only verified release objects and swaps matched installed bindings.
type DeploymentInstaller interface {
	StageDeployment(context.Context, Scope, DeploymentInstallRequest) (DeploymentReceipt, error)
	ActivateDeployment(context.Context, Scope, DeploymentInstallRequest) (DeploymentReceipt, error)
	RestoreDeployment(context.Context, Scope, RollbackRequest) (DeploymentReceipt, error)
}

type DeploymentCoordinator interface {
	PlanDeployment(context.Context, Scope, UpgradePlanRequest) (DeploymentPlan, error)
	ApplyDeployment(context.Context, Scope, UpgradeApplyRequest) (Operation, error)
	ReconcileDeployment(context.Context, Scope, ID) (Operation, error)
	RollbackDeployment(context.Context, Scope, RollbackRequest) (Operation, error)
}

type DeploymentStore interface {
	Deployment(context.Context, Scope, ID) (DeploymentPlan, error)
	FrozenBackup(context.Context, Scope, ID) (FrozenBackup, error)
}
