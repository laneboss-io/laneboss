//go:build !linux

package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (*leaseManager) credentialSource(context.Context, credentialSourceQuery) (api.CredentialProjectionAuthority, error) {
	return api.CredentialProjectionAuthority{}, failure(api.CodeUnsupported, "native credential metadata requires Linux")
}

func (*leaseManager) credentialObservation(context.Context, api.CredentialProjectionAuthority) (api.CredentialProjectionReceipt, error) {
	return api.CredentialProjectionReceipt{}, failure(api.CodeUnsupported, "native credential holding requires Linux")
}
