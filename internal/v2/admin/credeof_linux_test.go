//go:build linux

package admin

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// The foreign writer is a separate process that inherited the pinned caller's connected socket as descriptor 3. It
// writes one well-formed frame and exits, so the kernel fills that frame's SCM_CREDENTIALS with its own PID.
func init() {
	if len(os.Args) != 2 || os.Args[1] != "admin-credential-foreign-writer" {
		return
	}
	data, err := frame([]byte(`{"kind":"ordinary"}`))
	if err != nil {
		os.Exit(61)
	}
	if n, err := os.NewFile(3, "foreign-writer").Write(data); err != nil || n != len(data) {
		os.Exit(62)
	}
	os.Exit(0)
}

// Box 68 (serve2 a6c13b48): the component owner journaled "peer_mismatch pid uid gid got=0/0/0" against the pinned
// broker each time its one-shot caller closed. With SO_PASSCRED on, Linux attaches SCM_CREDENTIALS built from a
// zeroed cookie to a stream recvmsg that returns no bytes, so that read is the caller's close, not another writer's
// frame. A close between frames ends the stream; a close inside a frame is still a refused truncated frame.
func TestCredFrameCallerClose(t *testing.T) {
	for _, shape := range []string{"after-frame", "before-frame", "mid-frame"} {
		t.Run(shape, func(t *testing.T) {
			owner, caller := nativePair(t)
			peer := nativePeer(t, owner)
			data, err := frame([]byte(`{"kind":"ordinary"}`))
			if err != nil {
				t.Fatal(err)
			}
			if shape == "after-frame" {
				// credentialRemoteCall's shape: the pinned caller writes its one request, then closes.
				if n, err := caller.Write(data); err != nil || n != len(data) {
					t.Fatal("caller frame write failed")
				}
				body, files, err := readCredentialFrame(owner, peer.credentials, nil)
				if err != nil || len(files) != 0 || string(body) != `{"kind":"ordinary"}` {
					closeCredentialFiles(files)
					t.Fatalf("the pinned caller's own frame was refused: %v", err)
				}
			}
			if shape == "mid-frame" {
				if n, err := caller.Write(data[:7]); err != nil || n != 7 {
					t.Fatal("caller partial frame write failed")
				}
			}
			if err := caller.Close(); err != nil {
				t.Fatal(err)
			}
			_, files, err := readCredentialFrame(owner, peer.credentials, nil)
			closeErr := closeCredentialFiles(files)
			var typed *api.Error
			if !errors.As(err, &typed) || len(files) != 0 || closeErr != nil {
				t.Fatalf("the caller's close was not a typed refusal: %v", err)
			}
			if strings.Contains(typed.Message, "peer_mismatch") {
				t.Fatalf("the caller's close was read as another writer's credentials: %v", err)
			}
			if shape == "mid-frame" {
				if typed.Code != api.CodeUnauthenticated || !strings.Contains(typed.Message, "(closed)") {
					t.Fatalf("a frame cut by the caller's close was not refused as truncated: %v", err)
				}
			} else if typed.Code != api.CodeUnavailable || !strings.Contains(typed.Message, "closed") {
				t.Fatalf("the caller's close between frames was not named as a close: %v", err)
			}
		})
	}
}

// The negative case: another process writing on the pinned caller's connection is still refused by its own
// per-message SCM_CREDENTIALS, though SO_PEERCRED still names the connector.
func TestCredFrameForeignWriter(t *testing.T) {
	owner, caller := nativePair(t)
	peer := nativePeer(t, owner)
	inherited, err := caller.File()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/proc/self/exe", "admin-credential-foreign-writer")
	command.Env, command.ExtraFiles = []string{}, []*os.File{inherited}
	runErr := command.Run()
	if err := inherited.Close(); err != nil || runErr != nil || command.ProcessState.Pid() == os.Getpid() {
		t.Fatalf("foreign writer fixture failed: %v", runErr)
	}
	body, files, err := readCredentialFrame(owner, peer.credentials, nil)
	closeErr := closeCredentialFiles(files)
	var typed *api.Error
	if !errors.As(err, &typed) || body != nil || len(files) != 0 || closeErr != nil {
		t.Fatalf("a frame written by another process was accepted: %v", err)
	}
	if typed.Code != api.CodeUnauthenticated || !strings.Contains(typed.Message, "(peer_mismatch pid") {
		t.Fatalf("a frame written by another process was not refused as a peer mismatch: %v", err)
	}
}
