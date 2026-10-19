//go:build linux

package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Each acceptance guard has a distinct test and failure marker. The mutation
// runner requires that exact test's assertion, not just a nonzero test process.
// Native file/socket/UID observations below are component evidence; the full
// namespace/launch cells remain outside-CLI/socket acceptance in cases/admin.
func TestRestrictionOne(t *testing.T) {
	required, err := profileRequired([]byte(" 1\n"))
	if err != nil {
		t.Fatalf("restriction parse setup: %v", err)
	}
	if !required {
		t.Fatal("acceptance: restriction one ignored")
	}
	_, err = profileRequired([]byte("unknown"))
	requireCode(t, err, api.CodeUnsupported)
}

func TestRestrictionZero(t *testing.T) {
	required, err := profileRequired([]byte("0\n"))
	if err != nil {
		t.Fatalf("restriction parse setup: %v", err)
	}
	if required {
		t.Fatal("acceptance: needless profile required")
	}
}

func TestProfileAttachment(t *testing.T) {
	loaded := []byte("laneboss-bwrap (unconfined)\n")
	if err := verifyProfileState([]byte(bwrapProfile), loaded); err != nil {
		t.Fatalf("exact profile control: %v", err)
	}
	broad := strings.Replace(bwrapProfile, "/usr/bin/bwrap", "/**", 1)
	if broad == bwrapProfile {
		t.Fatal("profile control did not change its attachment")
	}
	err := verifyProfileState([]byte(broad), loaded)
	if err == nil {
		t.Fatal("acceptance: broad profile accepted")
	}
	requireCode(t, err, api.CodeIntegrity)
}

func TestProfileLoaded(t *testing.T) {
	if err := verifyProfileState([]byte(bwrapProfile), []byte("laneboss-bwrap (unconfined)\n")); err != nil {
		t.Fatalf("loaded profile control: %v", err)
	}
	err := verifyProfileState([]byte(bwrapProfile), []byte("another-profile (enforce)\n"))
	if err == nil {
		t.Fatal("acceptance: unloaded profile accepted")
	}
	requireCode(t, err, api.CodePrerequisite)
}

func TestHelperRootIDs(t *testing.T) {
	if err := verifyHelperIDs(0, 0, 0, 0); err != nil {
		t.Fatalf("root identity control: %v", err)
	}
	nonroot := os.Getpid() + 1000
	err := verifyHelperIDs(nonroot, nonroot, nonroot, nonroot)
	if err == nil {
		t.Fatal("acceptance: nonroot helper accepted")
	}
	requireCode(t, err, api.CodeForbidden)
}

func TestHelperSetID(t *testing.T) {
	nonroot := os.Getpid() + 1000
	for _, ids := range [][4]int{{nonroot, 0, nonroot, nonroot}, {0, 0, nonroot, 0}} {
		err := verifyHelperIDs(ids[0], ids[1], ids[2], ids[3])
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || !strings.Contains(typed.Message, "setuid or setgid") {
			t.Fatal("acceptance: setid refusal not reached")
		}
	}
}

func nativeArtifact(t *testing.T) (*os.File, api.ReleaseArtifact, unix.Stat_t) {
	t.Helper()
	f, err := os.Open("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	data, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	artifact := api.ReleaseArtifact{OS: "linux", Arch: runtime.GOARCH,
		Bytes: int64(len(data)), SHA256: api.Digest(hex.EncodeToString(sum[:]))}
	var info unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &info); err != nil {
		t.Fatal(err)
	}
	if err := verifyExecutableFile(f, artifact); err != nil {
		t.Fatalf("native artifact control: %v", err)
	}
	return f, artifact, info
}

func TestArtifactDigest(t *testing.T) {
	f, artifact, _ := nativeArtifact(t)
	// Keep the same descriptor, length, owner and mode. Only the supplied
	// digest changes, so another metadata guard cannot cover a missing hash.
	artifact.SHA256 = testDigest(string(artifact.SHA256) + "-different")
	err := verifyExecutableFile(f, artifact)
	if err == nil {
		t.Fatal("acceptance: changed digest accepted")
	}
	requireCode(t, err, api.CodeIntegrity)
}

func TestArtifactSetID(t *testing.T) {
	_, artifact, native := nativeArtifact(t)
	for _, bit := range []uint32{unix.S_ISUID, unix.S_ISGID} {
		changed := native
		changed.Mode |= bit
		err := verifyArtifactStat(changed, artifact)
		if err == nil {
			t.Fatal("acceptance: setid artifact accepted")
		}
		requireCode(t, err, api.CodeIntegrity)
	}
}

func TestFixedExecutable(t *testing.T) {
	root := privateTestDir(t)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		t.Fatal(err)
	}
	first, second := filepath.Join(root, "installed"), filepath.Join(root, "copy")
	if err := os.WriteFile(first, bytes[:], 0500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, bytes[:], 0500); err != nil {
		t.Fatal(err)
	}
	actual, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	copyInfo, err := os.Stat(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFileIdentity(actual, actual); err != nil {
		t.Fatalf("same inode control: %v", err)
	}
	err = verifyFileIdentity(copyInfo, actual)
	if err == nil {
		t.Fatal("acceptance: copied executable accepted")
	}
	requireCode(t, err, api.CodeIntegrity)
}

func TestServiceUIDDistinct(t *testing.T) {
	binding := testBinding()
	if err := binding.validate(); err != nil {
		t.Fatal(err)
	}
	binding.Lanes[0].UID = binding.Service.UID
	err := binding.validate()
	if err == nil {
		t.Fatal("acceptance: service UID shared")
	}
	requireCode(t, err, api.CodeIntegrity)
}

func TestRootPayloadFields(t *testing.T) {
	m, _, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	request := api.HelperLaunchRequest{LeaseID: lease.ID, PreparedSpecID: "spec", SpecSHA256: testDigest("spec"),
		Cause: testCause(api.InternalHelperPrepare, "life-a")}
	data, err := json.Marshal(credentialPrepare{Request: request})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.dispatch(context.Background(), "prepare", data)
	requireCode(t, err, api.CodeContainmentUnknown)
	for _, field := range []string{"argv", "path"} {
		var members map[string]json.RawMessage
		if err := json.Unmarshal(data, &members); err != nil {
			t.Fatal(err)
		}
		members[field] = json.RawMessage(`"/usr/bin/true"`)
		changed, err := json.Marshal(members)
		if err != nil {
			t.Fatal(err)
		}
		_, err = m.dispatch(context.Background(), "prepare", changed)
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
			t.Fatal("acceptance: root payload fields accepted")
		}
	}
}

func TestNativeUIDSurvivor(t *testing.T) {
	// The current test process is an independent, real live-UID canary. No
	// test-selected UID or claimed survivor count is supplied to production.
	err := uidQuiescent(context.Background(), uint32(os.Getuid()))
	if err == nil {
		t.Fatal("acceptance: live UID reported quiet")
	}
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown ||
		typed.Message != "lane UID still owns a live process; retain its lease" {
		t.Fatalf("UID probe did not reach its live canary: %v", err)
	}
}

func TestNativeClosedLifetime(t *testing.T) {
	reader, _ := nativePair(t)
	peer := nativePeer(t, reader)
	if err := peer.alive(); err != nil {
		t.Fatalf("live pidfd control: %v", err)
	}
	if err := unix.Close(peer.pidfd); err != nil {
		t.Fatal(err)
	}
	peer.pidfd = -1 // Cleanup cannot close an unrelated reused descriptor.
	err := peer.alive()
	if err == nil {
		t.Fatal("acceptance: closed lifetime accepted")
	}
	requireCode(t, err, api.CodeUnauthenticated)
}
