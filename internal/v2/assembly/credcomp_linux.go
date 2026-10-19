//go:build linux

package assembly

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/secrets/private"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type credentialPeerVerifier struct {
	api.PeerVerifier
	helper    *admin.Service
	installed Installation
}

func (p *credentialPeerVerifier) VerifyCredentialProjection(ctx context.Context, peer api.VerifiedPeer, a api.CredentialProjectionAuthority) error {
	pins, err := admin.LoadNativeCredentialPeers(p.installed.Config)
	if err != nil {
		return err
	}
	if a.InstallationGeneration != pins.Generation || a.ServiceUID != p.installed.ServiceUID || a.Helper.SHA256 != p.installed.ArtifactSHA256 || a.Broker != pins.Broker.Executable {
		return installError("credential projection changed its protected installation pins")
	}
	facts, err := peer.Facts(ctx)
	if err != nil {
		return err
	}
	if facts != a.HelperPeer {
		return installError("credential projection changed its actual native helper")
	}
	if err := p.helper.VerifyCredentialNativePeer(ctx, "helper", facts); err != nil {
		return err
	}
	return p.helper.VerifyCredentialNativePeer(ctx, "broker", a.BrokerPeer)
}

type credentialHelperPeer struct {
	helper *admin.Service
	facts  api.PeerFacts
}

func (p *credentialHelperPeer) Alive(ctx context.Context) error {
	return p.helper.VerifyCredentialNativePeer(ctx, "helper", p.facts)
}
func (p *credentialHelperPeer) Facts(ctx context.Context) (api.PeerFacts, error) {
	return p.facts, p.Alive(ctx)
}
func (p *credentialHelperPeer) Close() error { return p.Alive(context.Background()) }

type credentialArguments struct{ Arguments []json.RawMessage }
type credentialStorageInput struct {
	Name string `json:"name,omitempty"`
	Max  int64  `json:"max,omitempty"`
	Data []byte `json:"data,omitempty"`
	ID   api.ID `json:"id,omitempty"`
}

// This listener exposes only the broker's typed private metadata and encrypted
// storage ports. It is independent of the public human/lane dispatcher.
type credentialComponentSession struct {
	config          string
	helper          *admin.Service
	identity        *identity.Service
	methods         map[string]any
	secretDirectory string
	directory       *private.Directory
	locked          bool
	refresh         map[api.ID]*private.RefreshLease
}

func (s *credentialComponentSession) Close() (err error) {
	for _, lease := range s.refresh {
		err = errors.Join(err, lease.Close())
	}
	if s.directory != nil {
		err = errors.Join(err, s.directory.Close())
	}
	return err
}

func (s *credentialComponentSession) Call(ctx context.Context, peer api.VerifiedPeer, method string, raw json.RawMessage, files []*os.File) (any, []*os.File, error) {
	if len(files) != 0 {
		return nil, nil, installError("credential metadata cannot accept descriptors")
	}
	if strings.HasPrefix(method, "storage.") {
		value, err := s.storage(ctx, strings.TrimPrefix(method, "storage."), raw)
		return struct{ Value any }{value}, nil, err
	}
	if method == "identity.authorize" {
		var q struct {
			Peer    api.PeerFacts
			Request api.CredentialProjectionRequest
		}
		if err := api.DecodeObject(raw, &q); err != nil {
			return nil, nil, err
		}
		verified := &credentialHelperPeer{helper: s.helper, facts: q.Peer}
		value, err := s.identity.AuthorizeCredentialProjection(ctx, verified, q.Request)
		return struct{ Value any }{value}, nil, err
	}
	fn, found := s.methods[method]
	if !found {
		return nil, nil, installError("unknown private credential component method")
	}
	var input credentialArguments
	if err := api.DecodeObject(raw, &input); err != nil {
		return nil, nil, err
	}
	call := reflect.ValueOf(fn)
	if call.Type().NumIn() != len(input.Arguments)+1 {
		return nil, nil, installError("credential component argument count differs")
	}
	args := []reflect.Value{reflect.ValueOf(ctx)}
	for index, data := range input.Arguments {
		wrapped := reflect.New(reflect.StructOf([]reflect.StructField{{Name: "Value", Type: call.Type().In(index + 1)}}))
		if err := api.DecodeObject(data, wrapped.Interface()); err != nil {
			return nil, nil, err
		}
		argument := wrapped.Elem().Field(0)
		if scope, ok := argument.Interface().(api.Scope); ok && (scope.Config != s.config || scope.Actor != (api.Actor{Kind: "service", ID: "secrets"}) || scope.LaunchID != "" || scope.EndpointGeneration != 0 || scope.PolicyGeneration != 0) {
			return nil, nil, installError("credential component scope differs from its installed broker")
		}
		args = append(args, argument)
	}
	result := call.Call(args)
	if last := result[len(result)-1]; !last.IsNil() {
		return nil, nil, last.Interface().(error)
	}
	if len(result) == 1 {
		return struct{ Value api.Empty }{api.Empty{}}, nil, nil
	}
	return struct{ Value any }{result[0].Interface()}, nil, nil
}

func (s *credentialComponentSession) storage(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	var q credentialStorageInput
	if err := api.DecodeObject(raw, &q); err != nil {
		return nil, err
	}
	if q.Name != "" && (filepath.Base(q.Name) != q.Name || q.Name == "." || q.Name == "..") {
		return nil, installError("invalid encrypted record selector")
	}
	if s.directory == nil {
		d, err := private.Open(filepath.Join(s.secretDirectory, "records"))
		if err != nil {
			return nil, err
		}
		s.directory, s.refresh = d, make(map[api.ID]*private.RefreshLease)
	}
	d := s.directory
	if method == "lock" {
		if s.locked {
			return nil, installError("encrypted storage lock is already owned")
		}
		if err := d.Lock(ctx); err != nil {
			return nil, err
		}
		s.locked = true
		return api.Empty{}, nil
	}
	if strings.HasPrefix(method, "refresh_") {
		if method == "refresh_acquire" {
			if !s.locked || s.refresh[q.ID] != nil {
				return nil, installError("refresh acquisition lost its canonical journal lock")
			}
			lease, err := d.AcquireRefreshLease(q.ID)
			if err != nil {
				return nil, err
			}
			s.refresh[q.ID] = lease
			return api.Empty{}, nil
		}
		lease := s.refresh[q.ID]
		if lease == nil {
			return nil, installError("refresh lease has no original native owner")
		}
		switch method {
		case "refresh_check":
			return api.Empty{}, lease.Check()
		case "refresh_close":
			return api.Empty{}, lease.Close()
		case "refresh_held":
			held, err := lease.Held()
			return struct{ Held bool }{held}, err
		}
	}
	if !s.locked {
		return nil, installError("encrypted record operation lacks its canonical lock")
	}
	switch method {
	case "unlock":
		if err := d.Unlock(); err != nil {
			return nil, err
		}
		s.locked = false
		return api.Empty{}, nil
	case "names":
		return d.Names()
	case "read":
		if !credentialCiphertextName(q.Name) || q.Max <= 0 || q.Max > 256<<10 {
			return nil, installError("encrypted record read exceeds its native bound")
		}
		return d.Read(q.Name, q.Max)
	case "write":
		if !credentialCiphertextName(q.Name) || len(q.Data) == 0 || len(q.Data) > 256<<10 {
			return nil, installError("encrypted record write exceeds its native bound")
		}
		return api.Empty{}, d.Write(q.Name, q.Data)
	}
	return nil, installError("unknown private encrypted storage operation")
}

func credentialCiphertextName(name string) bool {
	if !strings.HasSuffix(name, ".json") {
		return false
	}
	id := strings.TrimSuffix(name, ".json")
	for _, prefix := range []string{".broker-profile-", ".broker-slot-", ".broker-login-", ".broker-projection-", ".broker-plan_cleanup-", ".key-"} {
		if strings.HasPrefix(id, prefix) {
			return wire.ID(strings.TrimPrefix(id, prefix))
		}
	}
	return wire.ID(id)
}

type credentialIdentitySession struct {
	helper   *admin.Service
	identity *identity.Service
}

func (s *credentialIdentitySession) Close() error { return nil }
func (s *credentialIdentitySession) Call(ctx context.Context, peer api.VerifiedPeer, method string, raw json.RawMessage, files []*os.File) (any, []*os.File, error) {
	if len(files) != 0 {
		return nil, nil, installError("credential identity cannot receive descriptors")
	}
	switch method {
	case "authorize":
		var q struct {
			Peer    api.PeerFacts
			Request api.CredentialProjectionRequest
		}
		if err := api.DecodeObject(raw, &q); err != nil {
			return nil, nil, err
		}
		if err := s.helper.VerifyCredentialNativePeer(ctx, "broker", q.Peer); err != nil {
			return nil, nil, err
		}
		value, err := s.identity.AuthorizeCredentialProjection(ctx, peer, q.Request)
		return value, nil, err
	case "check_launch":
		var q api.LaunchBindingRequest
		if err := api.DecodeObject(raw, &q); err != nil {
			return nil, nil, err
		}
		value, err := s.identity.CheckLaunchCredentials(ctx, q)
		return value, nil, err
	case "select_worker":
		var q api.PreparedSpecHandoff
		if err := api.DecodeObject(raw, &q); err != nil {
			return nil, nil, err
		}
		value, err := s.identity.SelectCredentialWorker(ctx, q)
		return value, nil, err
	}
	return nil, nil, installError("unknown private credential identity operation")
}
