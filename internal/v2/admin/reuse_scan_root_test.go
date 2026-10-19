//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/rscan"
)

func TestReuseRootJournal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("release journal control requires the disposable root box")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal("cannot generate journal canary")
	}
	key := []byte("sk-ant-" + hex.EncodeToString(entropy[:]))
	clear(entropy[:])
	defer clear(key)
	// The unit selector is random metadata independent of the key or its tail.
	var selector [8]byte
	if _, err := rand.Read(selector[:]); err != nil {
		t.Fatal("cannot generate unit selector")
	}
	config := "reuse-" + hex.EncodeToString(selector[:])
	unit := "laneboss-helper@" + config + ".service"
	log := func(data []byte) {
		command := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit="+unit, "/usr/bin/logger")
		command.Env, command.Stdin, command.Stdout, command.Stderr = []string{}, bytes.NewReader(data), io.Discard, io.Discard
		if err := command.Run(); err != nil {
			t.Fatal("journal control unit failed")
		}
		sync := exec.CommandContext(ctx, "/usr/bin/journalctl", "--sync")
		sync.Env = []string{}
		if err := sync.Run(); err != nil {
			t.Fatal("journal control synchronization failed")
		}
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if os.Mkdir(home, 0700) != nil {
		t.Fatal("cannot create journal control home")
	}
	info, err := os.Lstat(home)
	if err != nil {
		t.Fatal("cannot pin journal control home")
	}
	helper := filepath.Join(root, "helper")
	if os.WriteFile(helper, []byte("helper state\n"), 0600) != nil {
		t.Fatal("cannot retain journal control state")
	}
	inputs := rscan.APIKeyScanInputs{Home: home, HomeIdentity: info, HelperState: helper, Evidence: t.TempDir(),
		Journal: func(ctx context.Context, role string) (io.ReadCloser, error) {
			if role == "helper" {
				return openAPIKeyJournal(ctx, config, role)
			}
			return io.NopCloser(strings.NewReader("unit started\n")), nil
		}}
	log([]byte("ordinary journal control\n"))
	clean := rscan.ScanAPIKeyReleaseInputs(ctx, api.SecretMaterial{Bytes: key}, inputs)
	if !clean.Clean() {
		t.Fatal("actual journal reader failed its clean control", clean.Line())
	}
	for _, plant := range [][]byte{key[len(key)-8:], key} {
		log(plant)
		found := rscan.ScanAPIKeyReleaseInputs(ctx, api.SecretMaterial{Bytes: key}, inputs)
		if found.Clean() || !found[7].Last8 || found[7].Unreadable {
			t.Fatal("actual journal reader missed its planted-line control", found.Line())
		}
	}
}

func TestReuseNativeHome(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("native home control requires the disposable root box")
	}
	var selector [8]byte
	if _, err := rand.Read(selector[:]); err != nil {
		t.Fatal("cannot generate native scan selector")
	}
	binding := installation{Config: "reuse-" + hex.EncodeToString(selector[:])}
	q := api.CredentialProjectionRequest{Lease: api.HelperLease{ID: "lease-a"}, Home: api.PrivateHomeBinding{RootID: "home-a"},
		Prepared: api.PreparedLaunch{ID: "prepared-a", Target: api.LifeRef{LifeID: "life-a", Run: 1}},
		Handoff:  api.PreparedSpecHandoff{Config: binding.Config}}
	a := api.CredentialProjectionAuthority{ID: "projection-a", Request: q}
	record := leaseRecord{Lease: q.Lease, Storage: &launchStorageRecord{Ready: true, Binding: api.LaunchStorage{Home: q.Home, Target: q.Prepared.Target}},
		Spec: &specRegistration{Handoff: q.Handoff}, Gate: &gateJournal{Prepared: q.Prepared},
		Credentials: &credentialJournal{State: "withdrawing", Record: &api.CredentialProjectionRecord{Authority: a, Fence: &api.CredentialWithdrawalRequest{Reason: "release"}}}}
	base := filepath.Join("/var/lib/laneboss-v2/lanes", binding.Config)
	home := filepath.Join(storageBase(binding, record), string(q.Home.RootID))
	if os.MkdirAll(home, 0700) != nil {
		t.Fatal("cannot allocate retained native scan home")
	}
	t.Cleanup(func() {
		if os.RemoveAll(base) != nil {
			t.Error("cannot collect native scan fixture")
		}
	})
	var info unix.Stat_t
	if unix.Lstat(home, &info) != nil {
		t.Fatal("cannot measure native scan identity")
	}
	record.Storage.Directories = []storageIdentity{{ID: q.Home.RootID, Device: strconv.FormatUint(uint64(info.Dev), 10), Inode: strconv.FormatUint(info.Ino, 10)}}
	inputs, err := apiKeyReleaseInputs(binding, record, a, t.TempDir())
	if err != nil || inputs.Home != home || inputs.HomeIdentity == nil {
		t.Fatal("native scan failed its retained-home control")
	}
	// Exercise the production selector against the directory created by the
	// administrator installer, rather than supplying an evidence path ourselves.
	service := filepath.Join("/var/lib/laneboss-v2/service", binding.Config)
	if err := os.MkdirAll(service, 0700); err != nil {
		t.Fatal("cannot allocate installed service evidence")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(service); err != nil {
			t.Error("cannot collect installed service evidence")
		}
	})
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal("cannot generate independent evidence canary")
	}
	key := []byte("sk-ant-" + hex.EncodeToString(entropy[:]))
	clear(entropy[:])
	defer clear(key)
	manager := &leaseManager{binding: binding}
	clean, err := manager.scanReleaseAPIKey(context.Background(), record, *record.Credentials.Record, key)
	if err != nil || !clean[5].Present || clean[5].Unreadable || clean[5].Key || clean[5].Last8 {
		t.Fatal("native release scan selected absent evidence instead of the installed service directory")
	}
	if os.WriteFile(filepath.Join(service, "capture"), key, 0600) != nil {
		t.Fatal("cannot plant installed evidence control")
	}
	dirty, err := manager.scanReleaseAPIKey(context.Background(), record, *record.Credentials.Record, key)
	if err != nil || !dirty[5].Present || dirty[5].Unreadable || !dirty[5].Key || !dirty[5].Last8 || dirty.Clean() {
		t.Fatal("native release scan missed material in installed service evidence")
	}
	record.Storage.Directories[0].Inode = "0"
	if _, err := apiKeyReleaseInputs(binding, record, a, inputs.Evidence); err == nil {
		t.Fatal("native scan accepted a changed home identity")
	}
}
