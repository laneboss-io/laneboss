package dashboard

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// These private service operations are outside this projection fixture. Keep
// them failing: an accidental dependency must never look like a completed job.
var _ api.StateStore = (*memHarness)(nil)

func (*memHarness) CredentialProjection(context.Context, string, api.ID) (api.CredentialProjectionRecord, error) {
	return api.CredentialProjectionRecord{}, api.NotImplemented("lb-v2-service", "store.CredentialProjection")
}
func (*memHarness) ReserveCredentialProjection(context.Context, api.Scope, api.CredentialProjectionRequest) (api.CredentialProjectionRecord, error) {
	return api.CredentialProjectionRecord{}, api.NotImplemented("lb-v2-service", "store.ReserveCredentialProjection")
}
func (*memHarness) CommitCredentialProjection(context.Context, api.Scope, api.CredentialProjectionReceipt) (api.CredentialProjectionRecord, error) {
	return api.CredentialProjectionRecord{}, api.NotImplemented("lb-v2-service", "store.CommitCredentialProjection")
}
func (*memHarness) FenceCredentialProjection(context.Context, api.Scope, api.CredentialWithdrawalRequest) (api.CredentialProjectionRecord, error) {
	return api.CredentialProjectionRecord{}, api.NotImplemented("lb-v2-service", "store.FenceCredentialProjection")
}
func (*memHarness) CompleteCredentialWithdrawal(context.Context, api.Scope, api.CredentialWithdrawalReceipt) (api.CredentialProjectionRecord, error) {
	return api.CredentialProjectionRecord{}, api.NotImplemented("lb-v2-service", "store.CompleteCredentialWithdrawal")
}
func (*memHarness) CurrentApprovedPolicy(context.Context, api.Scope) (api.EffectivePolicy, error) {
	return api.EffectivePolicy{}, api.NotImplemented("lb-v2-service", "store.CurrentApprovedPolicy")
}

func (*memHarness) AppendCapture(context.Context, api.Scope, api.CaptureAppendRequest) (api.CaptureAppendReceipt, error) {
	return api.CaptureAppendReceipt{}, api.NotImplemented("lb-v2-service", "store.AppendCapture")
}
func (*memHarness) CaptureState(context.Context, api.Scope, api.ID) (api.CaptureState, error) {
	return api.CaptureState{}, api.NotImplemented("lb-v2-service", "store.CaptureState")
}
func (*memHarness) ReserveLaunch(context.Context, api.Scope, api.LaunchReservationRequest) (api.LaunchReservation, error) {
	return api.LaunchReservation{}, api.NotImplemented("lb-v2-service", "store.ReserveLaunch")
}
func (*memHarness) LaunchPlan(context.Context, api.Scope, api.ID) (api.LaunchPlanRecord, error) {
	return api.LaunchPlanRecord{}, api.NotImplemented("lb-v2-service", "store.LaunchPlan")
}
func (*memHarness) LaunchDataStage(context.Context, api.Scope, api.LaunchDataRequest) (api.LaunchDataStage, error) {
	return api.LaunchDataStage{}, api.NotImplemented("lb-v2-service", "store.LaunchDataStage")
}
func (*memHarness) PrepareChannelJob(context.Context, api.Scope, api.ChannelPrepareRequest) (api.ChannelJob, error) {
	return api.ChannelJob{}, api.NotImplemented("lb-v2-service", "store.PrepareChannelJob")
}
func (*memHarness) HumanEnrollments(context.Context, string) ([]api.HumanEnrollment, error) {
	return nil, api.NotImplemented("lb-v2-service", "store.HumanEnrollments")
}
func (*memHarness) ReserveEnrollment(context.Context, api.EnrollmentCeremonyRequest) (api.EnrollmentChallenge, error) {
	return api.EnrollmentChallenge{}, api.NotImplemented("lb-v2-service", "store.ReserveEnrollment")
}
func (*memHarness) EnrollmentChallenge(context.Context, string, api.ID) (api.EnrollmentChallenge, error) {
	return api.EnrollmentChallenge{}, api.NotImplemented("lb-v2-service", "store.EnrollmentChallenge")
}
func (*memHarness) WorkerBinding(context.Context, api.InstalledBinding, api.PeerFacts) (api.WorkerPrincipal, error) {
	return api.WorkerPrincipal{}, api.NotImplemented("lb-v2-service", "store.WorkerBinding")
}
func (*memHarness) LaunchRevocation(context.Context, api.ID) (api.LaunchRevocation, error) {
	return api.LaunchRevocation{}, api.NotImplemented("lb-v2-service", "store.LaunchRevocation")
}
func (*memHarness) RefreshReadSession(context.Context, api.Scope, api.ReadSessionRefreshRequest) (api.StoredReadSession, error) {
	return api.StoredReadSession{}, api.NotImplemented("lb-v2-service", "store.RefreshReadSession")
}
func (*memHarness) AwaitGuidance(context.Context, api.Scope, api.GuidanceAwaitRequest) (api.GuidanceReservation, error) {
	return api.GuidanceReservation{}, api.NotImplemented("lb-v2-service", "store.AwaitGuidance")
}
func (*memHarness) PolicyAt(context.Context, api.Scope, api.Generation) (api.EffectivePolicy, error) {
	return api.EffectivePolicy{}, api.NotImplemented("lb-v2-service", "store.PolicyAt")
}
func (*memHarness) RefreshLanePolicy(context.Context, api.Scope, api.PolicyAdvanceRequest) (api.PolicyAdvanceReceipt, error) {
	return api.PolicyAdvanceReceipt{}, api.NotImplemented("lb-v2-service", "store.RefreshLanePolicy")
}
