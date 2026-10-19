//go:build !linux

package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func loadInstallation(string) (installation, error) {
	return installation{}, failure(api.CodeUnsupported, "this administrator helper requires Linux; native Darwin belongs to its separately proved backend")
}

func runPlatformHelper(context.Context, string) error {
	return failure(api.CodeUnsupported, "Linux helper mode is unavailable on this platform")
}

func runFixedBootstrap(context.Context, string, string) error {
	return failure(api.CodeUnsupported, "Linux fixed bootstrap is unavailable on this platform")
}

func (m *leaseManager) startConfinedGate(context.Context, leaseRecord) (ownedGate, error) {
	return nil, failure(api.CodeUnsupported, "Linux prepared gates require Linux")
}

func (m *leaseManager) killContainment(context.Context, leaseRecord) error {
	return failure(api.CodeUnsupported, "Linux containment stop requires Linux")
}

func (m *leaseManager) killAndWait(context.Context, leaseRecord) error {
	return failure(api.CodeUnsupported, "native containment stop requires Linux")
}

func (m *leaseManager) waitContainmentEmpty(context.Context, leaseRecord) error {
	return failure(api.CodeUnsupported, "Linux containment events require Linux")
}

func (m *leaseManager) registerNativeCapture(context.Context, *leaseRecord, captureRegistration) (api.CaptureBinding, bool, error) {
	return api.CaptureBinding{}, false, failure(api.CodeUnsupported, "Linux capture requires Linux")
}

func (m *leaseManager) resolveNativeRuntime(context.Context, leaseRecord, api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	return api.ResolvedRuntime{}, failure(api.CodeUnsupported, "Linux runtime namespaces require Linux")
}

func (m *leaseManager) collectPrivateStorage(context.Context, *leaseRecord) error {
	return failure(api.CodeUnsupported, "Linux private storage collection requires Linux")
}

func (m *leaseManager) abortPrepared(context.Context, *leaseRecord, api.HelperAbortRequest) error {
	return failure(api.CodeUnsupported, "Linux prepared gate abort requires Linux")
}

func (m *leaseManager) collectNativeNetwork(context.Context, *leaseRecord) error {
	return failure(api.CodeUnsupported, "Linux network namespace collection requires Linux")
}

func (m *leaseManager) verifyCaptureSpool(context.Context, leaseRecord, captureJournal) error {
	return failure(api.CodeUnsupported, "Linux capture spool ownership requires Linux")
}

func (s *Service) call(context.Context, string, any, any) error {
	return failure(api.CodeUnsupported, "Linux helper transport is unavailable on this platform")
}

func (m *leaseManager) claudockPlanning(context.Context, string, claudockNativePlanning) (api.Empty, error) {
	return api.Empty{}, failure(api.CodeUnsupported, "native credential home planning requires Linux")
}

func workerServiceBinding(installation) (api.InstalledBinding, error) {
	return api.InstalledBinding{}, failure(api.CodeUnsupported, "Linux projected endpoint binding requires Linux")
}

func validateRuntimePins(context.Context, installation, api.LaunchSpec) error {
	return failure(api.CodeUnsupported, "Linux runtime enrollment is unavailable on this platform")
}

func loadLaunchEnrollment(context.Context, installation, api.BlobRef, api.BlobRef) (api.LaunchEnrollment, api.RuntimeManifest, error) {
	return api.LaunchEnrollment{}, api.RuntimeManifest{}, failure(api.CodeUnsupported, "Linux launch enrollment requires Linux")
}

func (s *Service) loadLaunchEnrollment(context.Context) (api.LaunchEnrollment, api.RuntimeManifest, error) {
	return api.LaunchEnrollment{}, api.RuntimeManifest{}, failure(api.CodeUnsupported, "Linux launch enrollment requires Linux")
}

func loadInstalledRuntime(context.Context, installation, api.BlobRef) (api.RuntimeManifest, error) {
	return api.RuntimeManifest{}, failure(api.CodeUnsupported, "Linux runtime enrollment requires Linux")
}

func validateAllocationEnrollment(context.Context, installation, launchAllocation) error {
	return failure(api.CodeUnsupported, "Linux launch storage requires Linux")
}

func (m *leaseManager) syncLaunchStorage(context.Context, *leaseRecord, bool) error {
	return failure(api.CodeUnsupported, "Linux launch storage requires Linux")
}

func (m *leaseManager) containment(context.Context, containmentQuery) (containmentTicket, error) {
	return containmentTicket{}, failure(api.CodeUnsupported, "Linux containment tickets require Linux")
}

func (m *leaseManager) revokeNativeContainment(context.Context, api.ID) (bool, error) {
	return false, failure(api.CodeUnsupported, "Linux containment revocation requires Linux")
}

func (s *Service) RegisterContainment(context.Context, api.ContainmentBinding) error {
	return failure(api.CodeUnsupported, "native Darwin containment requires its administrator backend")
}

func (s *Service) ResolveContainment(context.Context, api.PeerFacts, api.InstalledBinding) (api.ContainmentBinding, error) {
	return api.ContainmentBinding{}, failure(api.CodeUnsupported, "native Darwin containment resolution is unavailable")
}

func (s *Service) RevokeContainment(context.Context, api.ID) error {
	return failure(api.CodeUnsupported, "native Darwin containment revocation is unavailable")
}
