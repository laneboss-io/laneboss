//go:build !linux

package secrets

import (
	"laneboss.io/laneboss/internal/v2/api"
	"os"
)

func verifyProjectionHost(api.CredentialProjectionAuthority) error {
	return api.NotImplemented("lb-v2-secrets", "native credential projection process verification on this platform")
}
func exportCredential([]byte) (*os.File, error) {
	return nil, api.NotImplemented("lb-v2-secrets", "exclusive immutable native credential export on this platform")
}
func credentialFact(*os.File) (api.CredentialDescriptorFact, error) {
	return api.CredentialDescriptorFact{}, api.NotImplemented("lb-v2-secrets", "native credential descriptor observations on this platform")
}
