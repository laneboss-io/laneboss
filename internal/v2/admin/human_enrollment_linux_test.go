//go:build linux

package admin

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestEnrollmentEnvelope(t *testing.T) {
	_, _, _, _, endpoint := initialEnrollmentFixture(t)
	request := helperRequest{Protocol: enrollmentProtocol, Revision: api.ContractRevision, Config: endpoint.Config,
		Generation: endpoint.InstallationGeneration, ArtifactSHA256: endpoint.Helper.SHA256, Nonce: api.ID(strings.Repeat("a", 32)), Method: "enroll_begin"}
	if err := validateEnrollmentEnvelope(request, endpoint); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"protocol", "generation", "artifact", "method"} {
		t.Run(fault, func(t *testing.T) {
			changed := request
			switch fault {
			case "protocol":
				changed.Protocol = enrollmentProtocol + ".foreign"
			case "generation":
				changed.Generation++
			case "artifact":
				changed.ArtifactSHA256 = testDigest("uninstalled-artifact")
			case "method":
				changed.Method = "doctor"
			}
			if err := validateEnrollmentEnvelope(changed, endpoint); err == nil {
				t.Fatal("acceptance: administrator endpoint accepted a foreign entry")
			}
		})
	}
}

func TestEnrollmentNativeIdentityFields(t *testing.T) {
	if err := checkEnrollmentHelperStatus([]byte("Uid:\t0 0 0 0\nGid:\t0 0 0 0\n")); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"Uid:\t1000 0 0 0\nGid:\t0 0 0 0\n", "Uid:\t0 0 0 0\nGid:\t0 1000 0 0\n", "Uid:\t0 0 0 0\n"} {
		if err := checkEnrollmentHelperStatus([]byte(raw)); err == nil {
			t.Fatal("acceptance: administrator helper accepted nonroot or incomplete native identity")
		}
	}
}

func TestEnrollmentDispatchProtection(t *testing.T) {
	_, identity, store, _, endpoint := initialEnrollmentFixture(t)
	request := helperRequest{Method: "enroll_begin", Params: encodeLaunchFixture(t, identity.request.Ceremony)}
	_, err := dispatchEnrollment(context.Background(), endpoint, request, nil, store)
	if err == nil {
		t.Fatal("acceptance: public context reached administrator enrollment")
	}
}

// An adversarial callback returns a correlated reply without committing
// anything. The production dispatcher must demand independent read-back.
type uncommittedEnrollmentReply struct {
	identity *registrationIdentity
	calls    int
}

func (r *uncommittedEnrollmentReply) BeginHumanEnrollment(ctx context.Context, request api.EnrollmentCeremonyRequest) (api.EnrollmentChallenge, error) {
	return r.identity.BeginEnrollment(ctx, request)
}
func (r *uncommittedEnrollmentReply) CompleteHumanEnrollment(_ context.Context, request api.EnrollmentValidationRequest) (api.EnrollmentReceipt, error) {
	r.calls++
	if !reflect.DeepEqual(request, r.identity.request) {
		return api.EnrollmentReceipt{}, failure(api.CodeForbidden, "fixture adversary received a foreign request")
	}
	return api.EnrollmentReceipt{Config: request.Ceremony.Config, PrincipalID: request.Ceremony.PrincipalID, CeremonyID: request.Ceremony.CeremonyID,
		ChallengeID: request.ChallengeID, Generation: request.Ceremony.ExpectedGeneration + 1, Evidence: r.identity.install.CeremonyEvidence,
		OperationID: api.ID("uncommitted-" + string(request.Ceremony.CeremonyID)), EventID: api.ID("uncommitted-" + string(request.ChallengeID)), CommittedSeq: 1}, nil
}

func TestEnrollmentCompletionNeedsReadBack(t *testing.T) {
	_, identity, store, ctx, endpoint := initialEnrollmentFixture(t)
	adversary := &uncommittedEnrollmentReply{identity: identity}
	request := helperRequest{Method: "enroll_complete", Params: encodeLaunchFixture(t, identity.request)}
	_, err := dispatchEnrollment(ctx, endpoint, request, adversary, store)
	if err == nil || adversary.calls != 1 || store.installs != 0 || len(store.inventory) != 0 {
		t.Fatal("acceptance: administrator enrollment acknowledged callback success without read-back")
	}
}

func TestEnrollmentNativeACL(t *testing.T) {
	service := account{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	directory := privateTestDir(t)
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	var observed unix.Stat_t
	if err := unix.Lstat(directory, &observed); err != nil {
		t.Fatal(err)
	}
	if err := checkEnrollmentDirectoryStat(observed, service, true); err != nil {
		t.Fatal(err)
	}
	t.Run("directory", func(t *testing.T) {
		if err := os.Chmod(directory, 0750); err != nil {
			t.Fatal(err)
		}
		if err := unix.Lstat(directory, &observed); err != nil {
			t.Fatal(err)
		}
		if err := checkEnrollmentDirectoryStat(observed, service, true); err == nil {
			t.Fatal("acceptance: administrator enrollment directory permits shared access")
		}
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("ancestor", func(t *testing.T) {
		if err := os.Chmod(directory, 0777); err != nil {
			t.Fatal(err)
		}
		if err := unix.Lstat(directory, &observed); err != nil {
			t.Fatal(err)
		}
		if err := checkEnrollmentDirectoryStat(observed, service, false); err == nil {
			t.Fatal("acceptance: administrator enrollment accepted a writable ancestor")
		}
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
	})
	path := filepath.Join(directory, "control.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkEnrollmentSocket(path, service); err != nil {
		t.Fatal(err)
	}
	t.Run("socket", func(t *testing.T) {
		if err := os.Chmod(path, 0660); err != nil {
			t.Fatal(err)
		}
		if err := checkEnrollmentSocket(path, service); err == nil {
			t.Fatal("acceptance: administrator enrollment socket permits shared access")
		}
	})
}
