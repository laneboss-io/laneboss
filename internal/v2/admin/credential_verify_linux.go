//go:build linux

package admin

import (
	"context"
	"errors"
	"laneboss.io/laneboss/internal/v2/api"
	"os"
)

func (m *leaseManager) verifyCredentialNativePeer(ctx context.Context, q CredentialPeerVerification) (api.Empty, error) {
	if err := contextError(ctx); err != nil {
		return api.Empty{}, err
	}
	if m.credentials == nil {
		return api.Empty{}, failure(api.CodePrerequisite, "credential native owners are not bound")
	}
	if err := m.credentials.checkBinding(ctx); err != nil {
		return api.Empty{}, err
	}
	var facts api.PeerFacts
	switch q.Role {
	case "helper":
		generation, err := processGeneration(os.Getpid(), m.bootID)
		if err != nil {
			return api.Empty{}, err
		}
		group, err := cgroupMembership(os.Getpid())
		if err != nil || group != "/system.slice/laneboss-helper@"+m.binding.Config+".service/control" {
			return api.Empty{}, failure(api.CodeUnauthenticated, "credential helper lost its installed control containment")
		}
		file, err := os.Open("/proc/self/exe")
		if err != nil {
			return api.Empty{}, err
		}
		if err := errors.Join(verifyExecutableFile(file, m.binding.Artifact), file.Close()); err != nil {
			return api.Empty{}, err
		}
		facts = api.PeerFacts{HostPID: os.Getpid(), HostUID: uint32(os.Geteuid()), HostGID: uint32(os.Getegid()), ProcessGeneration: generation}
	case "broker":
		broker, ok := m.credentials.broker.(*nativeCredentialBroker)
		if !ok || broker == nil {
			return api.Empty{}, failure(api.CodeIntegrity, "credential broker lost its native channel")
		}
		var err error
		facts, err = broker.channel.Facts(ctx)
		if err != nil {
			return api.Empty{}, err
		}
	default:
		return api.Empty{}, failure(api.CodeInvalid, "unknown installed credential peer role")
	}
	if facts != q.Peer {
		return api.Empty{}, failure(api.CodeUnauthenticated, "credential peer differs from its measured native owner")
	}
	return api.Empty{}, nil
}
