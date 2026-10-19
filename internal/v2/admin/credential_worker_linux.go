//go:build linux

package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (b *nativeCredentialBroker) ReserveCredentials(ctx context.Context, peer api.VerifiedPeer, request api.CredentialProjectionRequest) (api.CredentialProjectionRecord, error) {
	var result api.CredentialProjectionRecord
	if err := peer.Alive(ctx); err != nil {
		return result, err
	}
	_, err := b.channel.call(ctx, "reserve", request, &result, nil, false)
	return result, err
}

func (i *nativeCredentialIdentity) SelectCredentialWorker(ctx context.Context, handoff api.PreparedSpecHandoff) (api.CredentialWorkerSelection, error) {
	var result api.CredentialWorkerSelection
	_, err := i.channel.call(ctx, "select_worker", handoff, &result, nil, false)
	return result, err
}
