//go:build !linux

package admin

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

func (r *credentialRuntime) checkBinding(context.Context) error {
	return failure(api.CodeUnsupported, "native credential attachment requires Linux")
}

func (m *leaseManager) bindCredentials(context.Context) credentialBindingResult {
	if m.credentialBindAttempted {
		return credentialBindingResult{Failure: failure(api.CodeConflict, "native credential binding is one-use")}
	}
	m.credentialBindAttempted = true
	return credentialBindingResult{Failure: failure(api.CodeUnsupported, "native credential receiver requires Linux")}
}
func (m *leaseManager) prepareCredentials(context.Context, credentialPrepare, api.PreparedLaunch) error {
	return failure(api.CodeUnsupported, "native credential preparation requires Linux")
}
func (m *leaseManager) openCredentialGate(context.Context, gateOpenRegistration) (api.ProcessHandle, error) {
	return api.ProcessHandle{}, failure(api.CodeUnsupported, "native credential guard requires Linux")
}
func (m *leaseManager) prepareCredentialExec(_ context.Context, record leaseRecord) (*credentialExecDelivery, error) {
	if record.Credentials == nil {
		return nil, nil
	}
	return nil, failure(api.CodeUnsupported, "credential exec requires Linux")
}

func (m *leaseManager) deliverCredentialExec(context.Context, leaseRecord, *credentialExecDelivery) error {
	return failure(api.CodeUnsupported, "native credential exec requires Linux")
}
func (m *leaseManager) awaitCredentialGate(context.Context, leaseRecord) error {
	return failure(api.CodeUnsupported, "native credential exec acknowledgement requires Linux")
}
func (m *leaseManager) withdrawProjection(_ context.Context, record *leaseRecord, _ api.InternalIntent, _ string) error {
	if record.Credentials == nil {
		return nil
	}
	return failure(api.CodeUnsupported, "native credential withdrawal requires Linux")
}
func (r *credentialRuntime) inspect(_ context.Context, t api.CredentialTransfer) ([]api.CredentialDescriptorFact, error) {
	return nil, errors.Join(failure(api.CodeUnsupported, "native credential descriptors require Linux"), closeCredentialFiles(t.Files))
}
func (r *credentialRuntime) project(_ context.Context, t api.CredentialTransfer) (api.CredentialProjectionReceipt, error) {
	return api.CredentialProjectionReceipt{}, errors.Join(failure(api.CodeUnsupported, "native credential holding requires Linux"), closeCredentialFiles(t.Files))
}
func (r *credentialRuntime) observe(context.Context, api.ID) (api.CredentialProjectionReceipt, error) {
	return api.CredentialProjectionReceipt{}, failure(api.CodeUnsupported, "native credential observation requires Linux")
}
func (r *credentialRuntime) withdraw(context.Context, api.CredentialProjectionRecord) (api.CredentialWithdrawalReceipt, error) {
	return api.CredentialWithdrawalReceipt{}, failure(api.CodeUnsupported, "native credential withdrawal requires Linux")
}
func (r *credentialRuntime) collectRefresh(context.Context, api.CredentialProjectionRecord) (api.CredentialRefresh, error) {
	return api.CredentialRefresh{}, failure(api.CodeUnsupported, "native credential refresh requires Linux")
}
