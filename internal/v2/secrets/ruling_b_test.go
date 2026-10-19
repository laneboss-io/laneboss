//go:build linux && laneboss_root_canary

package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

// Admin's native canary tests decide the exit/stop order. Here the production
// broker consumes that decision, actual sealed refresh bytes and an observed
// reaped process. This component model does not authenticate an installed helper.
func TestStopSeat(t *testing.T) {
	if os.Geteuid() == 0 {
		// Production exports from a root helper to an unprivileged broker.
		// Keep both identities real instead of weakening descriptor ownership.
		data, err := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]string{"account_id": "synthetic-account", "access_token": base64.StdEncoding.EncodeToString(syntheticBytes(t, 40)), "refresh_token": base64.StdEncoding.EncodeToString(syntheticBytes(t, 40))}, "last_refresh": time.Now().UTC().Format(time.RFC3339Nano)})
		if err != nil {
			t.Fatal(err)
		}
		defer clear(data)
		file, err := exportCredential(data)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		executable, err := os.Open("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		defer executable.Close()
		command := exec.Command("/proc/self/fd/4", "-test.run=^TestStopSeat$", "-test.v")
		command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
		command.ExtraFiles = []*os.File{file, executable}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("unprivileged broker failed: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	exported := os.NewFile(3, "root-refresh-export")
	defer exported.Close()
	refreshed, err := io.ReadAll(io.NewSectionReader(exported, 0, api.MaxFrameBytes))
	if err != nil || len(refreshed) == 0 {
		t.Fatal("root exporter did not supply refresh bytes")
	}
	defer clear(refreshed)
	for _, mode := range []string{"release", "running", "uncommitted", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			m, peer := projectionCase(t)
			s, ctx := m.c.service, context.Background()
			transfer, err := s.TransferCredentials(ctx, peer, m.a.Request)
			if err != nil {
				t.Fatal(err)
			}
			held, err := s.AcknowledgeCredentials(ctx, m.hold(t, transfer))
			if err != nil {
				t.Fatal(err)
			}
			cause := m.a.Request.Cause
			cause.ID, cause.Kind, cause.EffectID = "seat-stop", api.InternalHelperStop, "seat-stop-effect"
			reason := "release"
			if mode != "release" {
				reason = "revoked"
			}
			fenced, err := s.BeginCredentialWithdrawal(ctx, api.CredentialWithdrawalRequest{ProjectionID: m.a.ID, ExpectedGeneration: held.Generation, Cause: cause, Reason: reason})
			if err != nil {
				t.Fatal(err)
			}
			observation := m.c.finish(t, api.ProcessObservation{Handle: api.ProcessHandle{ID: "process-a", Target: m.c.target, ContainmentID: m.a.Request.Prepared.ContainmentID, Generation: m.a.Request.Prepared.ProcessGeneration}})
			observation.ObservedAt = api.Timestamp(m.c.clock.Now().Format(time.RFC3339Nano))
			zero := uint64(0)
			rotation := mode != "release"
			m.withdrawal = api.CredentialWithdrawalReceipt{ProjectionID: m.a.ID, Generation: fenced.Generation + 1, Cause: cause, Prepared: m.a.Request.Prepared, HelperLeaseID: m.a.Request.Lease.ID, Home: m.a.Request.Home, Observation: observation, RotationRequired: rotation, HelperDescriptors: &zero, ProjectedFiles: &zero, EnvironmentBuffers: &zero, OpenGates: &zero, ObservedAt: observation.ObservedAt}
			if !rotation {
				fd, err := unix.FcntlInt(exported.Fd(), unix.F_DUPFD_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				file := os.NewFile(uintptr(fd), "received-root-export")
				fact, err := credentialFact(file)
				if err != nil {
					file.Close()
					t.Fatal(err)
				}
				version, err := s.AcceptCredentialRefresh(ctx, peer, api.CredentialRefresh{ProjectionID: m.a.ID, ExpectedGeneration: fenced.Generation, SlotID: m.a.Targets[0].SlotID, ExpectedSourceGeneration: m.a.Sources[0].Generation, Observation: observation, Fact: fact, File: file})
				if err != nil || version.Generation <= m.a.Sources[0].Generation {
					t.Fatalf("release did not import the actual refresh: %v", err)
				}
			}
			done, err := s.FinishCredentialWithdrawal(ctx, fenced, m.withdrawal)
			if rotation {
				stageCode(t, err, api.CodeContainmentUnknown)
			} else if err != nil || done.State != "withdrawn" || done.Withdrawal == nil || done.Withdrawal.RotationRequired {
				t.Fatalf("late stop did not complete normal release: %v", err)
			}
			var owner bstate.Login
			if err := m.c.backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("login", m.c.profile.LoginID, &owner) }); err != nil {
				t.Fatal(err)
			}
			defer clear(owner.Material)
			if owner.Quarantined != rotation || (owner.SlotID == "") == rotation {
				t.Fatal("stop changed the wrong seat health or lease")
			}
			nextSeatLaunch(t, m.c)
			wait, cancel := context.WithTimeout(ctx, time.Second)
			next, err := m.c.acquire(wait, m.c.target, m.c.grant)
			cancel()
			if rotation {
				stageCode(t, err, api.CodeForbidden)
			} else {
				if err != nil || next.ID == m.a.Targets[0].SlotID || !bytes.Equal(owner.Material, refreshed) {
					t.Fatalf("healthy seat required rotation: %v", err)
				}
				slot := readCaseSlot(t, m.c, next.ID)
				defer clear(slot.Material)
				if !bytes.Equal(slot.Material, refreshed) {
					t.Fatal("later launch did not receive the imported refresh")
				}
			}
		})
	}
}

// A later start has its own reservation, grants, request and allocation.
// Replaying the released reservation must keep failing its idempotency gate.
func nextSeatLaunch(t *testing.T, c *launchCase) {
	t.Helper()
	prior := c.plan(t)
	r := prior.Reservation
	blob, err := c.store.Blob(context.Background(), api.Scope{}, api.BlobReadRequest{ObjectID: r.OriginalRequest.ID})
	if err != nil {
		t.Fatal(err)
	}
	var request api.Request
	if err := json.Unmarshal(blob.Data, &request); err != nil {
		t.Fatal(err)
	}
	request.RequestID, request.IdempotencyKey = "seat-next-request", "seat-next-key"
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	r.ID, r.LaunchID, r.SpecID = "seat-next-plan", "seat-next-launch", "seat-next-spec"
	r.Target.LifeID, r.RootLifeID = "seat-next-life", "seat-next-life"
	r.OperationID, r.RequestID, r.RequestSHA256 = "seat-next-operation", request.RequestID, request.RequestSHA256
	r.OriginalRequest = c.store.putObject(t, "seat-next-input", "launch_request", request, r.OperationID)
	c.store.grants.ID, c.store.grants.LifeID = "seat-next-grants", r.Target.LifeID
	grants := c.store.grants
	grants.SHA256 = ""
	c.store.grants.SHA256, err = valueDigest(grants)
	if err != nil {
		t.Fatal(err)
	}
	r.GrantSetID = c.store.grants.ID
	inputs := *prior.Inputs
	inputs.Grants, inputs.Sources.ReservationID = c.store.grants, r.ID
	c.store.planID, c.target = r.ID, r.Target
	record := api.LaunchPlanRecord{Reservation: r, Generation: 2, Phase: "sourced", Inputs: &inputs}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		t.Fatal(err)
	}
	c.setPlan(t, record)
	var effect api.EffectRecord
	if err := c.store.read("effect.json", &effect); err != nil {
		t.Fatal(err)
	}
	effect.Effect.OperationID, effect.Effect.PlanLaunch.ReservationID = r.OperationID, r.ID
	effect.Effect.Context.Target, effect.Effect.Context.CauseOperationID, effect.Effect.Context.CauseRequestID = r.Target, r.OperationID, r.RequestID
	if err := c.store.save("effect.json", effect); err != nil {
		t.Fatal(err)
	}
	var storage api.LaunchStorage
	if err := c.store.read("storage.json", &storage); err != nil {
		t.Fatal(err)
	}
	storage.ReservationID, storage.Target, storage.LeaseID = r.ID, r.Target, "seat-next-lease"
	storage.WorkspaceID, storage.Home.LifeID, storage.Home.RootID = "seat-next-work", r.Target.LifeID, "seat-next-root"
	storage.Home.Home.ID, storage.Home.Home.WorkspaceID, storage.Home.Home.HistoryID = "seat-next-home", storage.WorkspaceID, "seat-next-history"
	if err := c.store.save("storage.json", storage); err != nil {
		t.Fatal(err)
	}
	lease := api.HelperLease{ID: storage.LeaseID, UID: 12001, GID: 12001, ContainmentID: "seat-next-containment", EndpointGeneration: 1}
	payload, err := json.Marshal(lease)
	if err != nil {
		t.Fatal(err)
	}
	c.store.events = append(c.store.events, api.Event{Schema: api.SchemaVersion, ID: "seat-next-allocation", Seq: api.Sequence(len(c.store.events) + 1), Kind: "helper.allocated", Config: r.Config, Actor: effect.Effect.Context.Actor, RequestedBy: r.RequestedBy, RequestID: r.RequestID, OperationID: r.OperationID, LifeID: r.Target.LifeID, Run: r.Target.Run, Payload: payload})
}
