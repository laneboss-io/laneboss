package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// ResolveCommittedLaunchSources is an in-process read-only consumer of
// installer-bound object references. It runs the same full source selection
// used after native enrollment-file measurement by Service.ResolveLaunchSources.
// It does not install enrollment or attest a native executable or filesystem.
// Neither reference is a public request field or execution permission.
func ResolveCommittedLaunchSources(ctx context.Context, store api.StateStore, config string, request api.LaunchSourceRequest, enrollmentRef, runtimeRef api.BlobRef) (api.LaunchSources, error) {
	s := &Service{deps: Dependencies{Store: store, Config: config, LaunchEnrollment: &enrollmentRef, RuntimeManifest: runtimeRef}}
	authority, err := s.launchAuthority(ctx, request.ReservationID, request.GrantSetID, nil, request.Claim)
	if err != nil {
		return api.LaunchSources{}, err
	}
	enrollmentBytes, err := s.readLaunchObject(ctx, authority.Scope, enrollmentRef, "", "", true)
	if err != nil {
		return api.LaunchSources{}, err
	}
	runtimeBytes, err := s.readLaunchObject(ctx, authority.Scope, runtimeRef, "", "", true)
	if err != nil {
		return api.LaunchSources{}, err
	}
	var enrollment api.LaunchEnrollment
	var runtime api.RuntimeManifest
	if err := api.DecodeObject(enrollmentBytes, &enrollment); err != nil {
		return api.LaunchSources{}, err
	}
	if err := api.DecodeObject(runtimeBytes, &runtime); err != nil {
		return api.LaunchSources{}, err
	}
	return s.resolveLaunchSourceInputs(ctx, authority, enrollment, runtime)
}
