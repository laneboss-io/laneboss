//go:build linux

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/private"
)

type credentialReadSession struct {
	directory *private.Directory
	err       error
}

func (s *credentialReadSession) Call(_ context.Context, _ api.VerifiedPeer, _ string, raw json.RawMessage, _ []*os.File) (any, []*os.File, error) {
	var q struct {
		Name string `json:"name"`
		Max  int64  `json:"max"`
	}
	if err := json.Unmarshal(raw, &q); err != nil {
		return nil, nil, err
	}
	if s.err != nil {
		return nil, nil, s.err
	}
	data, err := s.directory.Read(q.Name, q.Max)
	return struct{ Value []byte }{data}, nil, err
}

func (s *credentialReadSession) Close() error { return s.directory.Close() }

// Exercise the real owner loop, native peer checks, framed reply, encrypted
// file read and stderr journal. No installed listener or model is started.
func credentialReadExchange(t *testing.T, method string, unsafe bool, callErr error) (credentialResponse, []byte) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal("cannot protect encrypted read fixture parent", err)
	}
	directoryPath := filepath.Join(parent, "records")
	directory, err := private.Open(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	name := ".broker-projection-first.json"
	if unsafe {
		path := filepath.Join(directoryPath, name)
		if err := os.WriteFile(path, []byte("untrusted ciphertext"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	}
	client, server := nativePair(t)
	control, err := server.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err := control.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
	}); err != nil || optionErr != nil {
		t.Fatal("cannot enable native writer credentials", err, optionErr)
	}
	peer := nativePeer(t, client)
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	group, err := cgroupMembership(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	journal, err := os.Create(filepath.Join(parent, "owner.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stderr
	os.Stderr = journal
	defer func() {
		os.Stderr = previous
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	binding := installation{Config: "credential-read-case", Generation: 1}
	binding.Artifact.SHA256 = testDigest("credential-read-owner")
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		serveCredentialOwner(ctx, server, binding, strings.TrimSpace(string(boot)), CredentialOwnerOptions{
			CallerUID: uint32(os.Getuid()), CallerGID: uint32(os.Getgid()), CallerCgroup: group,
			VerifyCaller: func(ctx context.Context, peer api.VerifiedPeer) error { return peer.Alive(ctx) },
			NewSession:   func() CredentialOwnerSession { return &credentialReadSession{directory: directory, err: callErr} },
		})
	}()
	defer func() {
		client.Close()
		server.Close()
		<-finished
	}()
	params, err := json.Marshal(struct {
		Name string `json:"name"`
		Max  int64  `json:"max"`
	}{name, 2048})
	if err != nil {
		t.Fatal(err)
	}
	request := helperRequest{Protocol: credentialProtocol, Revision: api.ContractRevision,
		Config: binding.Config, Generation: binding.Generation, ArtifactSHA256: binding.Artifact.SHA256,
		Nonce: "credential-read-once", Method: method, Params: params}
	if err := writeFrame(client, request); err != nil {
		t.Fatal(err)
	}
	raw, err := readUnixFrame(client, peer)
	if err != nil {
		t.Fatal("credential owner did not reply to the actual read", err)
	}
	var response credentialResponse
	if err := decodeStrict(raw, &response); err != nil || response.Nonce != request.Nonce {
		t.Fatal("credential read response lost its request binding", err)
	}
	client.Close()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("credential owner did not close its completed read session")
	}
	logged, err := os.ReadFile(journal.Name())
	if err != nil {
		t.Fatal(err)
	}
	return response, logged
}

func TestCredentialOwnerStorageReadJournal(t *testing.T) {
	for _, test := range []struct {
		name    string
		method  string
		unsafe  bool
		err     error
		code    api.ErrorCode
		owner   string
		refused bool
	}{
		{name: "expected-absent", method: "storage.read", code: api.CodeNotFound, owner: "lb-v2-secrets"},
		{name: "unsafe-record", method: "storage.read", unsafe: true, code: api.CodeIntegrity, owner: "lb-v2-secrets", refused: true},
		{name: "required-record", method: "transfer", code: api.CodeNotFound, owner: "lb-v2-secrets", refused: true},
		{name: "other-owner", method: "storage.read", err: &api.Error{Code: api.CodeNotFound, Owner: "lb-v2-admin"}, code: api.CodeNotFound, owner: "lb-v2-admin", refused: true},
		{name: "same-message-real-refusal", method: "storage.read", err: &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-secrets", Message: "encrypted secret record is absent"}, code: api.CodeForbidden, owner: "lb-v2-secrets", refused: true},
		{name: "joined-real-refusal", method: "storage.read", err: errors.Join(&api.Error{Code: api.CodeNotFound, Owner: "lb-v2-secrets"}, &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-secrets"}), code: api.CodeNotFound, owner: "lb-v2-secrets", refused: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, journal := credentialReadExchange(t, test.method, test.unsafe, test.err)
			if response.Error == nil || response.Error.Code != test.code || response.Error.Owner != test.owner || len(response.Result) != 0 {
				t.Fatal("credential read failure was swallowed or changed", response.Error)
			}
			lines := bytes.Split(bytes.TrimSpace(journal), []byte{'\n'})
			if !test.refused {
				if len(bytes.TrimSpace(journal)) != 0 {
					t.Errorf("expected-absent storage probe was journaled as a refusal: %s", journal)
				}
				return
			}
			var event struct {
				Event  string        `json:"event"`
				Method string        `json:"method"`
				Code   api.ErrorCode `json:"code"`
				Owner  string        `json:"owner"`
			}
			if len(lines) != 1 || json.Unmarshal(lines[0], &event) != nil || event.Event != "credential_owner_refused" || event.Method != test.method || event.Code != test.code || event.Owner != test.owner {
				t.Fatalf("real credential refusal lost its typed journal record: %s", journal)
			}
		})
	}
}
