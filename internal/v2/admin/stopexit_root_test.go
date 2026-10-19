//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// This metadata peer reads the actual refresh export and refuses completion.
// Native cleanup is real; broker policy is covered separately by secrets,
// not manufactured by this helper fixture.
type exitBroker struct {
	api.CredentialProjectionBroker
	projection api.CredentialProjectionRecord
	refreshed  []byte
	receipt    *api.CredentialWithdrawalReceipt
	refusal    error
	imports    int
}

func (b *exitBroker) BeginCredentialWithdrawal(_ context.Context, q api.CredentialWithdrawalRequest) (api.CredentialProjectionRecord, error) {
	if err := api.ValidateCredentialWithdrawalRequest(b.projection, q); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	b.projection.State = "withdrawing"
	b.projection.Generation++
	b.projection.Fence = &q
	return b.projection, nil
}

func (b *exitBroker) AcceptCredentialRefresh(_ context.Context, _ api.VerifiedPeer, refresh api.CredentialRefresh) (api.CredentialSourceVersion, error) {
	if err := api.ValidateCredentialRefresh(b.projection, refresh, time.Now()); err != nil {
		return api.CredentialSourceVersion{}, err
	}
	fact, err := credentialDescriptor(refresh.File, true)
	if err != nil || !reflect.DeepEqual(fact, refresh.Fact) {
		return api.CredentialSourceVersion{}, errors.New("refresh export changed")
	}
	data, err := io.ReadAll(io.NewSectionReader(refresh.File, 0, fact.Size))
	if err != nil || int64(len(data)) != fact.Size {
		return api.CredentialSourceVersion{}, errors.New("refresh export was incomplete")
	}
	b.refreshed = data
	b.imports++
	return api.CredentialSourceVersion{Key: refresh.SlotID, Generation: refresh.ExpectedSourceGeneration + 1, Version: string(digestBytes(data))}, nil
}

func (b *exitBroker) FinishCredentialWithdrawal(_ context.Context, p api.CredentialProjectionRecord, receipt api.CredentialWithdrawalReceipt) (api.CredentialProjectionRecord, error) {
	if err := api.ValidateCredentialWithdrawalHelper(p, receipt); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	b.receipt = &receipt
	return api.CredentialProjectionRecord{}, b.refusal
}

func init() {
	if len(os.Args) != 2 || os.Args[1] != "stop-refresh-ns" {
		return
	}
	runtime.LockOSThread()
	if unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil || unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "") != nil {
		os.Exit(71)
	}
	os.Args = []string{os.Args[0], "-test.run=^TestStopRefresh$", "-test.v"}
}

func TestStopRefresh(t *testing.T) {
	if os.Getpid() != 1 {
		// Give the full /proc scanner a dedicated process population. Other
		// root canaries and host services may retain unrelated namespaces.
		// The production scanner and all of its refusal checks stay intact.
		executable, err := os.Open("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		defer executable.Close()
		command := exec.Command("/proc/self/fd/3", "stop-refresh-ns")
		command.Env = []string{}
		command.ExtraFiles = []*os.File{executable}
		command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS | unix.CLONE_NEWPID}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated helper failed: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	for _, mode := range []string{"after-exit", "running", "uncommitted"} {
		t.Run(mode, func(t *testing.T) {
			exited := mode == "after-exit"
			m, reg, _, store, owner, _, file := stopCredentialFixture(t, true)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			request := stopExitRequest(reg)
			r, err := m.find(request.Target.LeaseID)
			if err != nil {
				t.Fatal(err)
			}
			_, stat, err := credentialObject(file)
			if err != nil {
				t.Fatal(err)
			}
			held := m.credentials.held[r.Credentials.Record.Authority.ID]
			held.destinations = []storageInode{{Device: uint64(stat.Dev), Inode: stat.Ino}}
			data, err := io.ReadAll(io.NewSectionReader(file, 0, stat.Size))
			if err != nil {
				t.Fatal(err)
			}
			defer clear(data)
			broker := &exitBroker{projection: *r.Credentials.Record, refusal: errors.New("outside completion unavailable")}
			defer func() { clear(broker.refreshed) }()
			m.credentials.broker = broker
			if exited {
				naturalCanaryExit(t, ctx, owner)
				if _, err := m.observeGate(ctx, request.Target); err != nil {
					t.Fatal(err)
				}
			} else if mode == "uncommitted" {
				naturalCanaryExit(t, ctx, owner)
				refuseExitCommit(t, ctx, m, request.Target)
			}
			_, err = m.stopGate(ctx, request)
			if !errors.Is(err, broker.refusal) {
				t.Fatalf("helper did not reach measured completion: %v", err)
			}
			if broker.receipt == nil || broker.receipt.RotationRequired == exited || (broker.imports == 1) != exited || exited && !bytes.Equal(broker.refreshed, data) {
				t.Fatal("stop lost the release refresh or running rotation")
			}
			records, err := store.Records()
			if err != nil || len(records) != 1 || (records[0].Credentials.Refresh != nil) != exited || records[0].Revoked == exited {
				t.Fatal("stop did not retain the measured refresh decision")
			}
			if exited {
				journal := records[0].Credentials
				before := *journal
				before.Refresh = nil
				if err := credentialRecoveryTransition(&before, journal); err != nil {
					t.Fatal("late stop could not append its refresh receipt")
				}
				changed := *journal
				version := *journal.Refresh
				version.Generation++
				changed.Refresh = &version
				if credentialRecoveryTransition(journal, &changed) == nil || credentialRecoveryTransition(journal, &before) == nil {
					t.Fatal("recovery replaced or erased an acknowledged refresh")
				}
			}
		})
	}
}
