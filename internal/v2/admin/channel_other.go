//go:build !linux

package admin

import "context"

func (m *leaseManager) startChannelGate(context.Context, leaseRecord, channelNative) (ownedGate, error) {
	return nil, failure("unsupported", "native channel gate requires Linux")
}

func (s *Service) bindChannelContainment(context.Context, channelReg) error {
	return failure("unsupported", "native channel containment requires Linux")
}
