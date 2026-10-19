package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

func (c *launchCase) addSecret(t *testing.T, name, delivery, target string) (api.SecretGrant, []byte) {
	t.Helper()
	value := syntheticBytes(t, 107)
	info, err := c.backend.Store(context.Background(), api.SecretInfo{Name: name, Version: "one"}, api.SecretMaterial{Bytes: value})
	if err != nil {
		t.Fatal("cannot enroll synthetic task source")
	}
	grant := api.SecretGrant{ID: api.ID("grant-" + name), Name: name, Version: info.Version, SourceHandle: info.SourceHandle, Delivery: delivery, Target: target, ExpiresAt: c.store.grants.ExpiresAt}
	c.store.grants.Secrets = append(c.store.grants.Secrets, grant)
	copy := c.store.grants
	copy.SHA256 = ""
	digest, err := valueDigest(copy)
	if err != nil {
		t.Fatal("cannot hash resolved fixture grants")
	}
	c.store.grants.SHA256 = digest
	record := c.plan(t)
	record.Inputs.Grants = c.store.grants
	c.setPlan(t, record)
	return grant, value
}

func readCaseSlot(t *testing.T, c *launchCase, id api.ID) bstate.Slot {
	t.Helper()
	var slot bstate.Slot
	if err := c.backend.WithBroker(context.Background(), func(journal bstate.Journal) error { return journal.Read("slot", id, &slot) }); err != nil {
		t.Fatal("cannot inspect protected test slot")
	}
	return slot
}

func TestReservedCredentialLifecycle(t *testing.T) {
	c := newLaunchCase(t, "headless_token")
	ctx := context.Background()
	env, envValue := c.addSecret(t, "env-canary", "env", "TASK_TOKEN")
	file, fileValue := c.addSecret(t, "file-canary", "file", "service/token")
	slot, err := c.acquire(ctx, c.target, c.grant)
	if err != nil || slot.ID == "" || slot.ProfileID != c.grant.ProfileID {
		t.Fatal("reserved-life profile acquisition did not prepare a real slot")
	}
	if c.store.lane != nil {
		t.Fatal("credential acquisition fabricated a ready lane")
	}
	protected := readCaseSlot(t, c, slot.ID)
	if !bytes.Equal(protected.Material, c.material) || protected.Target != c.target || protected.ReservationID != c.store.planID {
		t.Fatal("reserved profile slot lost actual material or reservation binding")
	}
	clear(protected.Material)
	before, err := os.ReadFile(filepath.Join(c.backendDirectory(), ".broker-slot-"+string(slot.ID)+".json"))
	if err != nil {
		t.Fatal("cannot retain profile slot ciphertext")
	}
	replayed, err := c.acquire(ctx, c.target, c.grant)
	if err != nil || replayed != slot {
		t.Fatal("reserved profile retry did not return its original slot")
	}
	after, err := os.ReadFile(filepath.Join(c.backendDirectory(), ".broker-slot-"+string(slot.ID)+".json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("reserved profile retry rewrote its ciphertext")
	}
	injection, err := c.inject(ctx, c.target, []api.SecretGrant{env, file})
	if err != nil || len(injection.SlotIDs) != 3 || !reflect.DeepEqual(injection.GrantIDs, []api.ID{env.ID, file.ID}) {
		t.Fatal("reserved-life injection did not retain its exact selected slots")
	}
	for i, want := range [][]byte{envValue, fileValue} {
		actual := readCaseSlot(t, c, injection.SlotIDs[i+1])
		if !bytes.Equal(actual.Material, want) {
			t.Fatal("prepared task slot differs from actual delegated bytes")
		}
		clear(actual.Material)
	}
	observation := c.bind(t, slot, injection)
	material, err := c.service.SlotMaterial(ctx, "launch-a", slot.ID)
	if err != nil || !bytes.Equal(material.Bytes, c.material) {
		t.Fatal("bound credential material lookup lost its exact protected bytes")
	}
	clear(material.Bytes)
	_, err = c.service.SlotMaterial(ctx, "foreign-launch", slot.ID)
	stageCode(t, err, api.CodeForbidden)
	zero, exit := uint64(0), 0
	forged := observation
	forged.State, forged.Survivors, forged.ExitCode = "exited", &zero, &exit
	stageCode(t, c.service.Release(ctx, slot, forged), api.CodeContainmentUnknown)
	observation = c.finish(t, observation)
	if err := c.service.RevokeInjection(ctx, injection, observation); err != nil {
		t.Fatal("measured injection cleanup did not release actual slots")
	}
	for _, id := range injection.SlotIDs {
		actual := readCaseSlot(t, c, id)
		if !actual.Released || len(actual.Material) != 0 || len(actual.Returned) != 0 {
			t.Fatal("credential cleanup left retained material active")
		}
	}
	if c.helper.releases != 1 {
		t.Fatal("one containment cleanup issued multiple helper releases")
	}
	if err := c.service.RevokeInjection(ctx, injection, observation); err != nil {
		t.Fatal("measured injection cleanup did not replay")
	}
	entries, err := os.ReadDir(c.backendDirectory())
	if err != nil {
		t.Fatal("cannot inspect encrypted broker files")
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(c.backendDirectory(), entry.Name()))
		if err != nil {
			t.Fatal("cannot inspect encrypted broker bytes")
		}
		for _, value := range [][]byte{c.material, envValue, fileValue, []byte(base64.StdEncoding.EncodeToString(c.material))} {
			if bytes.Contains(data, value) {
				t.Fatal("credential material escaped the encrypted broker store")
			}
		}
	}
}

func (c *launchCase) backendDirectory() string { return c.directory }

func TestReservationGuards(t *testing.T) {
	for _, fault := range []string{"claim", "foreign", "epoch", "resolved", "policy", "grants", "path", "executable", "source-executable", "request", "storage", "history", "original-origin", "runtime"} {
		t.Run(fault, func(t *testing.T) {
			c := newLaunchCase(t, "headless_token")
			record := c.plan(t)
			expected := api.CodeForbidden
			switch fault {
			case "claim":
				var effect api.EffectRecord
				if err := c.store.read("effect.json", &effect); err != nil {
					t.Fatal("cannot read claim control")
				}
				effect.ClaimExpiresAt = api.Timestamp(c.clock.now.Format(time.RFC3339Nano))
				if err := c.store.save("effect.json", effect); err != nil {
					t.Fatal("cannot expire claim control")
				}
				expected = api.CodeConflict
			case "foreign":
				record.Reservation.Config = "foreign-case"
			case "epoch":
				record.Reservation.CancellationEpoch++
			case "resolved":
				record.Inputs.Grants.Profiles[0].Paid = true
				expected = api.CodeConflict
			case "policy":
				c.store.policy.Generation++
				expected = api.CodeConflict
			case "grants":
				c.store.grants.Revoked = true
			case "path":
				record.Inputs.Sources.Runtime.Executable.ID = "/caller/executable"
				expected = api.CodeInvalid
			case "executable":
				profile := c.profile
				profile.Runtime.SHA256 = digestFixture("caller runtime")
				if err := c.backend.WithBroker(context.Background(), func(j bstate.Journal) error { return j.Write("profile", profile.ID, profile) }); err != nil {
					t.Fatal("cannot alter protected profile executable control")
				}
				expected = api.CodeForbidden
			case "source-executable":
				record.Inputs.Sources.Runtime.Executable.SHA256 = digestFixture("changed source runtime")
				expected = api.CodeConflict
			case "runtime":
				record.Inputs.Sources.Runtime.Executable.ID = "caller-runtime"
				expected = api.CodeConflict
			case "request":
				record.Reservation.RequestSHA256 = digestFixture("changed original request")
				expected = api.CodeIntegrity
			case "storage":
				var storage api.LaunchStorage
				if err := c.store.read("storage.json", &storage); err != nil {
					t.Fatal("cannot read registry control")
				}
				storage.Home.LifeID = "foreign-life"
				if err := c.store.save("storage.json", storage); err != nil {
					t.Fatal("cannot alter registry control")
				}
			case "history":
				var storage api.LaunchStorage
				if err := c.store.read("storage.json", &storage); err != nil {
					t.Fatal("cannot read history control")
				}
				storage.Home.Home.ID = credentialID("profile", record.Reservation.ID, c.grant.ID)
				if err := c.store.save("storage.json", storage); err != nil {
					t.Fatal("cannot alter home control")
				}
			case "original-origin":
				meta := c.store.objects[record.Reservation.OriginalRequest.ID]
				meta.ACL.Owner.Kind = "lane"
				c.store.objects[meta.Ref.ID] = meta
			}
			if fault != "grants" {
				c.setPlan(t, record)
			}
			if fault == "foreign" {
				selector, err := c.selection(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				_, err = c.service.reservedPlan(context.Background(), c.target, selector)
				stageCode(t, err, expected)
			}
			_, err := c.acquire(context.Background(), c.target, c.grant)
			stageCode(t, err, expected)
		})
	}
}

func TestCredentialChangedRetryAndRestart(t *testing.T) {
	c := newLaunchCase(t, "headless_token")
	slot, err := c.acquire(context.Background(), c.target, c.grant)
	if err != nil {
		t.Fatal("cannot establish retained slot retry control")
	}
	record := c.plan(t)
	record.Reservation.RequestID = "changed-request"
	// Change the retained envelope and reservation consistently. The same
	// reservation/slot ID still cannot replay against changed original inputs.
	blob, err := c.store.Blob(context.Background(), api.Scope{}, api.BlobReadRequest{ObjectID: record.Reservation.OriginalRequest.ID})
	if err != nil {
		t.Fatal("cannot read retained request control")
	}
	var request api.Request
	if json.Unmarshal(blob.Data, &request) != nil {
		t.Fatal("cannot decode retained request control")
	}
	request.RequestID = record.Reservation.RequestID
	record.Reservation.OriginalRequest = c.store.putObject(t, "changed-original", "launch_request", request, record.Reservation.OperationID)
	var effect api.EffectRecord
	if err := c.store.read("effect.json", &effect); err != nil {
		t.Fatal("cannot read original claim")
	}
	effect.Effect.Context.CauseRequestID = record.Reservation.RequestID
	if err := c.store.save("effect.json", effect); err != nil {
		t.Fatal("cannot change original claim")
	}
	for i := range c.store.events {
		c.store.events[i].RequestID = record.Reservation.RequestID
	}
	c.setPlan(t, record)
	_, err = c.acquire(context.Background(), c.target, c.grant)
	stageCode(t, err, api.CodeConflict)
	protected := readCaseSlot(t, c, slot.ID)
	if !bytes.Equal(protected.Material, c.material) {
		t.Fatal("changed retry replaced protected slot bytes")
	}
	clear(protected.Material)
	if err := c.backend.Close(); err != nil {
		t.Fatal("cannot restart credential backend")
	}
	c.backend = openMutationBackend(t, c.backendDirectory(), c.clock, c.key)
	service, err := New(Dependencies{ProjectionIdentity: deniedProjection{}, Backend: c.backend, Store: c.store, Human: &humanFixture{}, Clock: c.clock, Config: "service-case", Grants: &launchCaseResolver{store: c.store, clock: c.clock}, Helper: c.helper, Control: c.control})
	if err != nil {
		t.Fatal("cannot reopen credential service")
	}
	c.service = service
	_, err = c.service.SlotMaterial(context.Background(), "launch-a", slot.ID)
	stageCode(t, err, api.CodeNotFound)
}

func TestProfileRoomEvidence(t *testing.T) {
	c := newLaunchCase(t, "helper")
	room, err := c.service.Room(context.Background(), c.grant)
	if err != nil || !room.Available || room.Evidence != c.profile.Evidence {
		t.Fatal("profile room did not use actual protected evidence")
	}
	var observation bstate.Observation
	data, err := c.store.Blob(context.Background(), api.Scope{}, api.BlobReadRequest{ObjectID: c.profile.Evidence.ID})
	if err != nil || json.Unmarshal(data.Data, &observation) != nil {
		t.Fatal("cannot read quota control")
	}
	observation.Available = false
	ref := c.store.putObject(t, c.profile.Evidence.ID, "credential_evidence", observation, "observation-operation")
	profile := c.profile
	profile.Evidence = ref
	if err := c.backend.WithBroker(context.Background(), func(journal bstate.Journal) error { return journal.Write("profile", profile.ID, profile) }); err != nil {
		t.Fatal("cannot publish changed protected quota observation")
	}
	room, err = c.service.Room(context.Background(), c.grant)
	if err != nil || room.Available {
		t.Fatal("profile room ignored a measured unavailable result")
	}
	c.clock.now = c.clock.now.Add(4 * time.Minute)
	_, err = c.service.Room(context.Background(), c.grant)
	stageCode(t, err, api.CodeForbidden)
}

func TestReleaseGuards(t *testing.T) {
	for _, fault := range []string{"binding", "identity", "generation", "disagreement", "resource", "record", "foreign-slot"} {
		t.Run(fault, func(t *testing.T) {
			c := newLaunchCase(t, "headless_token")
			slot, err := c.acquire(context.Background(), c.target, c.grant)
			if err != nil {
				t.Fatal("cannot prepare measured release control")
			}
			injection, err := c.inject(context.Background(), c.target, []api.SecretGrant{})
			if err != nil {
				t.Fatal("cannot prepare empty task selection")
			}
			observation := c.bind(t, slot, injection)
			observation = c.finish(t, observation)
			expected := api.CodeContainmentUnknown
			switch fault {
			case "binding":
				c.store.fail["binding"] = &api.Error{Code: api.CodeNotFound, Owner: "lb-v2-service", Message: "fixture retained binding is absent"}
				expected = api.CodeNotFound
			case "generation":
				observation.Handle.Generation = "foreign-generation"
			case "disagreement":
				code := 42
				observation.ExitCode = &code
			case "identity":
				var binding api.LaunchBindingRequest
				if err := c.store.read("binding.json", &binding); err != nil {
					t.Fatal("cannot read identity receipt control")
				}
				binding.Identity.CommittedSeq = 0
				if err := c.store.save("binding.json", binding); err != nil {
					t.Fatal("cannot alter identity receipt control")
				}
				expected = api.CodeInvalid
			case "resource":
				if err := os.WriteFile(filepath.Join(c.helper.root, "exports", "live-export"), []byte("owned resource"), 0600); err != nil {
					t.Fatal("cannot create live resource control")
				}
			case "record":
				c.control.omitRecord = true
				expected = api.CodeIntegrity
			case "foreign-slot":
				slot.ProfileID = "foreign-profile"
				expected = api.CodeForbidden
			}
			stageCode(t, c.service.Release(context.Background(), slot, observation), expected)
			retained := readCaseSlot(t, c, slot.ID)
			defer clear(retained.Material)
			if retained.Released || !bytes.Equal(retained.Material, c.material) {
				t.Fatal("failed cleanup erased or released protected credentials")
			}
		})
	}
}

func TestFileLoginRefresh(t *testing.T) {
	c := newLaunchCase(t, "file_login")
	ctx := context.Background()
	slot, err := c.acquire(ctx, c.target, c.grant)
	if err != nil {
		t.Fatal("cannot acquire serialized file login")
	}
	injection, err := c.inject(ctx, c.target, []api.SecretGrant{})
	if err != nil {
		t.Fatal("cannot bind file-login selection")
	}
	observation := c.bind(t, slot, injection)
	var returned map[string]string
	if json.Unmarshal(c.material, &returned) != nil {
		t.Fatal("cannot decode actual enrolled file login")
	}
	returned["refresh_token"] = base64.StdEncoding.EncodeToString(syntheticBytes(t, 41))
	returned["access_token"] = base64.StdEncoding.EncodeToString(syntheticBytes(t, 42))
	data, err := json.Marshal(returned)
	if err != nil {
		t.Fatal("cannot encode actual refreshed file login")
	}
	bad := map[string]string{}
	for key, value := range returned {
		bad[key] = value
	}
	bad["account_id"] = "foreign-account"
	changed, err := json.Marshal(bad)
	if err != nil {
		t.Fatal("cannot encode changed identity control")
	}
	stageCode(t, c.service.ReturnSlot(ctx, "launch-a", slot.ID, api.SecretMaterial{Bytes: changed}), api.CodeForbidden)
	if err := c.service.ReturnSlot(ctx, "launch-a", slot.ID, api.SecretMaterial{Bytes: data}); err != nil {
		t.Fatal("supported refresh fields were refused")
	}
	observation = c.finish(t, observation)
	if err := c.service.Release(ctx, slot, observation); err != nil {
		t.Fatal("measured file-login release did not import supported refresh")
	}
	profile, err := c.service.loadProfile(ctx, c.grant)
	if err != nil {
		t.Fatal("cannot reload refreshed protected profile")
	}
	var owner bstate.Login
	if err := c.backend.WithBroker(ctx, func(journal bstate.Journal) error { return journal.Read("login", profile.LoginID, &owner) }); err != nil || owner.SlotID != "" {
		t.Fatal("quiescent refresh did not free its canonical owner")
	}
	defer clear(owner.Material)
	if owner.RefreshSlotID != slot.ID || !bytes.Equal(owner.Material, data) {
		t.Fatal("refresh import did not preserve actual returned bytes")
	}
	actual, err := c.backend.Fetch(ctx, profile.Source)
	if err != nil || !bytes.Equal(actual.Bytes, c.material) {
		t.Fatal("canonical refresh changed the immutable enrolled source")
	}
	clear(actual.Bytes)
}

func TestCredentialDependenciesPropagate(t *testing.T) {
	c := newLaunchCase(t, "headless_token")
	failure := api.NotImplemented("lb-v2-admin", "admin.ResolveLaunchStorage")
	c.helper.fail["storage"] = failure
	_, err := c.acquire(context.Background(), c.target, c.grant)
	if err != failure {
		t.Fatal("credential launch swallowed the owning helper dependency refusal")
	}
	failure = api.NotImplemented("lb-v2-service", "store.LaunchPlan")
	c.helper.fail["storage"] = nil
	c.store.fail["plan"] = failure
	_, err = c.inject(context.Background(), c.target, []api.SecretGrant{})
	if err != failure {
		t.Fatal("credential injection swallowed the owning store dependency refusal")
	}
}

func TestRunnerSlotRead(t *testing.T) {
	for _, mode := range []string{"valid", "claim", "home", "slot", "released", "profile", "source"} {
		t.Run(mode, func(t *testing.T) {
			c := newLaunchCase(t, "codex-file")
			ctx := context.Background()
			slot, err := c.acquire(ctx, c.target, c.grant)
			if err != nil {
				t.Fatal(err)
			}
			port, ok := any(c.service).(interface {
				VerifyRunnerSlot(context.Context, api.LaunchClaim, api.RunnerRequest) (api.LaunchStorage, error)
			})
			if !ok {
				t.Fatal("broker has no protected live runner slot read")
			}
			selection, err := c.selection(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var storage api.LaunchStorage
			if err := c.store.read("storage.json", &storage); err != nil {
				t.Fatal(err)
			}
			request := api.RunnerRequest{Target: c.target, Home: storage.Home.Home, Slot: slot, Executable: c.profile.Runtime, Model: c.profile.Models[0]}
			switch mode {
			case "claim":
				selection.Claim.ClaimID = "other-claim"
			case "home":
				request.Home.ID = "other-home"
			case "slot":
				request.Slot.LeaseID = "other-lease"
			case "released":
				saved := readCaseSlot(t, c, slot.ID)
				saved.Released = true
				if err := c.backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Write("slot", saved.ID, saved) }); err != nil {
					t.Fatal(err)
				}
				clear(saved.Material)
				clear(saved.Returned)
			case "profile":
				changed := c.profile
				changed.Generation++
				if err := c.backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Write("profile", changed.ID, changed) }); err != nil {
					t.Fatal(err)
				}
			case "source":
				var source api.SecretInfo
				if err := c.backend.WithMetadata(ctx, func(infos []api.SecretInfo) error {
					for _, info := range infos {
						if info.SourceHandle == c.profile.Source.SourceHandle {
							source = info
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if source.SourceHandle == "" {
					t.Fatal("actual source metadata is missing")
				}
				if err := c.backend.Revoke(ctx, source); err != nil {
					t.Fatal(err)
				}
			}
			actual, err := port.VerifyRunnerSlot(ctx, selection.Claim, request)
			if mode == "valid" {
				if err != nil || actual != storage {
					t.Fatal("actual encrypted slot did not verify its storage", err)
				}
				replay, err := port.VerifyRunnerSlot(ctx, selection.Claim, request)
				if err != nil || replay != actual {
					t.Fatal("slot read replaced its acquisition", err)
				}
			} else if err == nil {
				t.Fatal("changed slot authority passed", mode)
			}
		})
	}
}
