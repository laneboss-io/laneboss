//go:build linux

package dataworker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func projectionIdentity(t *testing.T, path string) string {
	t.Helper()
	var info unix.Stat_t
	if err := unix.Lstat(path, &info); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%d:%d", info.Dev, info.Ino)
}

func TestMaterializationRootPin(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "workspace")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	identity := projectionIdentity(t, path)
	root, err := openMaterializationRoot(path, identity, uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		t.Fatal("native projection could not open its exact private root", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := os.Rename(path, filepath.Join(parent, "retained")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	marker := []byte(identity)
	if err := root.WriteFile("inside", marker, 0600); err != nil {
		t.Fatal("held projection could not write its actual private workspace", err)
	}
	actual, err := os.ReadFile(filepath.Join(parent, "retained", "inside"))
	if err != nil || string(actual) != string(marker) {
		t.Fatal("descriptor-root handoff followed a replaced path", err)
	}
	if _, err := os.Lstat(filepath.Join(path, "inside")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("held projection wrote to a pathname replacement", err)
	}
	if actual, _, err := rootIdentity(root); err != nil || actual != identity {
		t.Fatal("retained projection lost its helper inode identity", err)
	}
}

func TestMaterializationRootGuards(t *testing.T) {
	for _, fault := range []string{"identity", "uid", "gid", "mode", "leaf-link", "parent-link", "file"} {
		t.Run(fault, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "root")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			identity, uid, gid := projectionIdentity(t, path), uint32(os.Geteuid()), uint32(os.Getegid())
			switch fault {
			case "identity":
				identity = projectionIdentity(t, parent)
			case "uid":
				uid++
			case "gid":
				gid++
			case "mode":
				if err := os.Chmod(path, 0750); err != nil {
					t.Fatal(err)
				}
			case "leaf-link":
				link := filepath.Join(parent, "alias")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "parent-link":
				link := filepath.Join(parent, "alias")
				if err := os.Symlink(parent, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "root")
			case "file":
				path = filepath.Join(parent, "regular")
				if err := os.WriteFile(path, []byte(identity), 0700); err != nil {
					t.Fatal(err)
				}
				identity = projectionIdentity(t, path)
			}
			root, err := openMaterializationRoot(path, identity, uid, gid)
			if err == nil {
				t.Fatal("native bridge accepted a changed or linked root", root.Close())
			}
			var refusal *api.Error
			if !errors.As(err, &refusal) || refusal.Code != api.CodeIntegrity && refusal.Code != api.CodeContainmentUnknown {
				t.Fatal("native bridge lost its typed root refusal", err)
			}
		})
	}
}

type nativeInputFixture struct {
	api.WorkerBootstrap
	path  string
	calls int
	err   error
}

func (b *nativeInputFixture) WorkerInput(context.Context, api.Scope, api.WorkerInputRequest) (api.WorkerJobInput, error) {
	b.calls++
	if b.err != nil {
		return api.WorkerJobInput{}, b.err
	}
	data, err := os.ReadFile(b.path)
	return api.WorkerJobInput{Bytes: data}, err
}

func TestNativeWorkerInputAgreement(t *testing.T) {
	for _, fault := range []string{"valid", "bytes", "whitespace", "transport"} {
		t.Run(fault, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "retained-input")
			local := []byte("{\n  \"stage\": \"retained-job\"\n}\n")
			remote := append([]byte(nil), local...)
			if fault == "bytes" {
				remote[18] ^= 1
			}
			if fault == "whitespace" {
				remote = append(remote, '\n')
			}
			if err := os.WriteFile(path, remote, 0600); err != nil {
				t.Fatal(err)
			}
			server := &nativeInputFixture{path: path}
			failure := errors.New("native input transport control")
			if fault == "transport" {
				server.err = failure
			}
			bridge := sealedWorkerBootstrap{WorkerBootstrap: server, input: local}
			input, err := bridge.WorkerInput(context.Background(), api.Scope{}, api.WorkerInputRequest{})
			if server.calls != 1 {
				t.Fatal("native bridge replaced its authenticated input read")
			}
			if fault == "valid" {
				if err != nil || string(input.Bytes) != string(local) {
					t.Fatal("native bridge changed its authenticated exact-byte input", err)
				}
			} else if fault == "transport" {
				if !errors.Is(err, failure) {
					t.Fatal("native bridge swallowed a failed authenticated read", err)
				}
			} else {
				var refusal *api.Error
				if !errors.As(err, &refusal) || refusal.Code != api.CodeIntegrity {
					t.Fatal("native bridge accepted changed service input bytes", err)
				}
			}
		})
	}
}
