//go:build linux

package admin

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type NativeCredentialPeers = credentialPeerCatalog

func LoadNativeCredentialPeers(config string) (NativeCredentialPeers, error) {
	var peers NativeCredentialPeers
	binding, err := loadInstallation(config)
	if err != nil {
		return peers, err
	}
	data, err := readProtected(filepath.Join("/etc/laneboss-v2/credential-peers", config+".json"), api.MaxFrameBytes)
	if err != nil {
		return peers, err
	}
	if err := decodeStrict(data, &peers); err != nil {
		return peers, err
	}
	if peers.Schema != "laneboss.credential-peers.v2" || peers.Config != config || peers.Generation != binding.Generation || peers.Broker.UID == 0 || peers.Broker.UID == binding.Service.UID || peers.Identity.UID != binding.Service.UID || peers.Identity.GID != binding.Service.GID {
		return peers, failure(api.CodeIntegrity, "credential peer catalog differs from the installed generation")
	}
	for _, lane := range binding.Lanes {
		if lane.UID == peers.Broker.UID {
			return peers, failure(api.CodeIntegrity, "credential broker is in the lane UID pool")
		}
	}
	return peers, nil
}

type CredentialComponentClient struct {
	channel *credentialChannel
	peer    *credentialOwnerPeer
}

func DialCredentialComponent(ctx context.Context, config string) (*CredentialComponentClient, error) {
	binding, err := loadInstallation(config)
	if err != nil {
		return nil, err
	}
	peers, err := LoadNativeCredentialPeers(config)
	if err != nil {
		return nil, err
	}
	if uint32(os.Geteuid()) != peers.Broker.UID || uint32(os.Getegid()) != peers.Broker.GID {
		return nil, failure(api.CodeForbidden, "credential metadata client requires its installed outside broker")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(binding.credentialRuntimePath(), "component.sock")
	if err := protectedPath(filepath.Dir(path), true); err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != peers.Identity.UID || st.Gid != peers.Broker.GID || st.Mode&07777 != 0660 {
		return nil, failure(api.CodeUnavailable, "credential metadata endpoint lacks protected publication")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, failure(api.CodeUnavailable, "credential metadata endpoint is unavailable")
	}
	conn := connection.(*net.UnixConn)
	peer, err := pinPeer(conn, peers.Identity.UID, peers.Identity.GID)
	if err != nil {
		conn.Close()
		return nil, err
	}
	bootID := strings.TrimSpace(string(boot))
	generation, err := processGeneration(int(peer.credentials.Pid), bootID)
	if err != nil {
		conn.Close()
		closePeer(peer)
		return nil, err
	}
	verified := &credentialOwnerPeer{peer: peer, boot: bootID, generation: generation, cgroup: peers.Identity.Cgroup, containment: peers.Identity.ContainmentID}
	if err := verified.Alive(ctx); err != nil {
		conn.Close()
		verified.Close()
		return nil, err
	}
	// Only the helper can publish this endpoint. Its separate original identity
	// channel measures the service executable; this metadata transport pins that
	// dedicated UID, installed cgroup, socket-bound pidfd and process generation.
	channel := &credentialChannel{connection: conn, peer: peer, binding: binding, boot: bootID}
	return &CredentialComponentClient{channel, verified}, nil
}

func (c *CredentialComponentClient) Call(ctx context.Context, method string, input, output any) error {
	if err := c.peer.Alive(ctx); err != nil {
		return err
	}
	nonce, err := randomID("credential-meta-")
	if err != nil {
		return err
	}
	params, err := EncodeWire(input)
	if err != nil {
		return err
	}
	b := c.channel.binding
	request := helperRequest{Protocol: credentialProtocol, Revision: api.ContractRevision, Config: b.Config, Generation: b.Generation, ArtifactSHA256: b.Artifact.SHA256, Nonce: nonce, Method: method, Params: params}
	if attempt, ok := api.EffectLeaseFromContext(ctx); ok {
		request.Attempt = &attempt
	}
	c.channel.mu.Lock()
	defer c.channel.mu.Unlock()
	_, err = c.channel.exchange(ctx, request, output, nil, false, time.Now().Add(10*time.Second), func() error { return c.peer.Alive(ctx) })
	return err
}
func (c *CredentialComponentClient) Close() error {
	return errors.Join(c.channel.connection.Close(), c.peer.Close())
}
