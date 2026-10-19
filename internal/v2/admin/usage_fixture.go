//go:build linux && (!laneboss_partial || !laneboss_e2e_authenticator)

package admin

import "laneboss.io/laneboss/internal/v2/api"

func usageFixtureRuntime(api.RuntimeManifest, []*nativeMount, api.Executable, string) (bool, error) {
	return false, nil
}
func (m *leaseManager) watchdogProviderMount(api.RuntimeManifest, []*nativeMount) (*nativeMount, error) {
	return nil, nil
}
