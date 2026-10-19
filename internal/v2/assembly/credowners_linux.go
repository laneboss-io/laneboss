//go:build linux

package assembly

import (
	"context"
	"errors"
	"io"
	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/service"
	"path/filepath"
)

func installedCredentialPeers(peers api.PeerVerifier, helper *admin.Service, installed Installation) api.PeerVerifier {
	return &credentialPeerVerifier{peers, helper, installed}
}

type credentialOwnerCloser struct{ close func() error }

func (c credentialOwnerCloser) Close() error { return c.close() }

func startInstalledCredentialOwners(ctx context.Context, installed Installation, helper *admin.Service, identity *identity.Service, state api.StateStore, grants *grants.Service, control *service.Server) (io.Closer, error) {
	pins, err := admin.LoadNativeCredentialPeers(installed.Config)
	if err != nil {
		return nil, err
	}
	methods := map[string]any{
		"store.CredentialProjection": state.CredentialProjection, "store.ReserveCredentialProjection": state.ReserveCredentialProjection, "store.CommitCredentialProjection": state.CommitCredentialProjection,
		"store.FenceCredentialProjection": state.FenceCredentialProjection, "store.CompleteCredentialWithdrawal": state.CompleteCredentialWithdrawal,
		"store.CurrentApprovedPolicy": state.CurrentApprovedPolicy, "store.Policy": state.Policy, "store.Effect": state.Effect, "store.Grants": state.Grants, "store.LaunchPlan": state.LaunchPlan,
		"store.LaunchBinding": state.LaunchBinding, "store.WorkerLease": state.WorkerLease, "store.Lane": state.Lane, "store.ObjectMetadata": state.ObjectMetadata, "store.Blob": state.Blob,
		"grants.Resolve": grants.Resolve, "grants.Revalidate": grants.Revalidate,
		"helper.ResolveRuntime": helper.ResolveCredentialRuntime, "helper.ObserveCredentials": helper.ObserveCredentials, "helper.ObserveGate": helper.ObserveCredentialGate, "helper.ReadCredentialWithdrawal": helper.ReadCredentialWithdrawal,
		"control.Handoff": control.Handoff, "control.Open": control.Open, "identity.CheckLaunchCredentials": identity.CheckLaunchCredentials,
		"peer.VerifyHelper": func(ctx context.Context, facts api.PeerFacts) error {
			return helper.VerifyCredentialNativePeer(ctx, "helper", facts)
		},
	}
	verify := func(role string) func(context.Context, api.VerifiedPeer) error {
		return func(ctx context.Context, peer api.VerifiedPeer) error {
			facts, err := peer.Facts(ctx)
			if err != nil {
				return err
			}
			return helper.VerifyCredentialNativePeer(ctx, role, facts)
		}
	}
	ownerDirectory := filepath.Join(admin.CredentialRuntimeDirectory(installed.Config), "owners", "identity")
	closeIdentity, err := admin.ListenCredentialOwner(ctx, admin.CredentialOwnerOptions{Config: installed.Config, Path: filepath.Join(ownerDirectory, "credential-identity.sock"), OwnerUID: pins.Identity.UID, OwnerGID: pins.Identity.GID,
		CallerUID: 0, CallerGID: 0, CallerCgroup: "/system.slice/laneboss-helper@" + installed.Config + ".service/control", VerifyCaller: verify("helper"), NewSession: func() admin.CredentialOwnerSession {
			return &credentialIdentitySession{helper: helper, identity: identity}
		}})
	if err != nil {
		return nil, err
	}
	closeComponent, err := admin.ListenCredentialOwner(ctx, admin.CredentialOwnerOptions{Config: installed.Config, Path: filepath.Join(ownerDirectory, "credential-component.sock"), OwnerUID: pins.Identity.UID, OwnerGID: pins.Identity.GID,
		CallerUID: pins.Broker.UID, CallerGID: pins.Broker.GID, CallerCgroup: pins.Broker.Cgroup, CallerContainment: pins.Broker.ContainmentID, VerifyCaller: verify("broker"),
		NewSession: func() admin.CredentialOwnerSession {
			return &credentialComponentSession{config: installed.Config, helper: helper, identity: identity, methods: methods, secretDirectory: installed.SecretDirectory}
		}})
	if err != nil {
		return nil, errors.Join(err, closeIdentity())
	}
	return credentialOwnerCloser{func() error { return errors.Join(closeComponent(), closeIdentity()) }}, nil
}
