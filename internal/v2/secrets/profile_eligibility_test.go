package secrets

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

func (c *launchCase) syncGrants(t *testing.T) {
	t.Helper()
	copy := c.store.grants
	copy.SHA256 = ""
	digest, err := valueDigest(copy)
	if err != nil {
		t.Fatal("cannot hash exact fixture grants")
	}
	c.store.grants.SHA256 = digest
	record := c.plan(t)
	record.Inputs.Grants = c.store.grants
	c.setPlan(t, record)
}

func (c *launchCase) installOtherProfile(t *testing.T) (api.ProfileGrant, bstate.Profile) {
	return c.installProfileAlias(t, "canonical-login-b")
}

func (c *launchCase) installProfileAlias(t *testing.T, login api.ID) (api.ProfileGrant, bstate.Profile) {
	t.Helper()
	grant, profile := c.grant, c.profile
	grant.ID, grant.ProfileID = "profile-grant-b", "profile-b"
	profile.ID, profile.LoginID = grant.ProfileID, login
	observation := bstate.Observation{Schema: "laneboss.credential-evidence.v2", Config: "service-case", ProfileID: profile.ID, LoginID: profile.LoginID, Generation: profile.Generation, Driver: profile.Driver, Provider: profile.Provider,
		Available: true, CheckedAt: api.Timestamp(c.clock.now.Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(c.clock.now.Add(3 * time.Minute).Format(time.RFC3339Nano))}
	profile.Evidence = c.store.putObject(t, "profile-evidence-b", "credential_evidence", observation, "observation-operation-b")
	if err := c.service.InstallProfile(context.Background(), profile); err != nil {
		t.Fatal("cannot install the second protected profile")
	}
	declared := false
	for _, member := range c.store.grants.Profiles {
		declared = declared || member == grant
	}
	if !declared {
		t.Fatal("alternate profile was not declared before launch reservation")
	}
	return grant, profile
}

func eligibilityCase(t *testing.T) (*launchCase, api.ProfileEligibilityRequest, bstate.Profile) {
	t.Helper()
	c := newLaunchCaseWithAlternate(t, "helper")
	c.registeredCapture = true
	grant, profile := c.installOtherProfile(t)
	slot, err := c.acquire(context.Background(), c.target, c.grant)
	if err != nil {
		t.Fatal("cannot prepare the original eligibility profile")
	}
	injection, err := c.inject(context.Background(), c.target, []api.SecretGrant{})
	if err != nil {
		t.Fatal("cannot prepare original eligibility injection")
	}
	c.bind(t, slot, injection)
	request := api.ProfileEligibilityRequest{Target: c.target, GrantSetID: c.store.grants.ID, FromGrantID: c.grant.ID, ToGrantID: grant.ID, Driver: c.grant.Driver, Model: c.store.lane.Model, Session: c.store.lane.Session, HistoryID: c.store.lane.Session.HistoryID}
	return c, request, profile
}

func TestProtectedProfileEligibility(t *testing.T) {
	c, request, profile := eligibilityCase(t)
	actual, err := c.service.Eligibility(context.Background(), request)
	if err != nil || !actual.Compatible || actual.ID == "" || actual.Request != request || actual.Evidence != profile.Evidence {
		t.Fatal("compatible enrolled profiles did not retain exact eligibility and evidence")
	}
	blob, err := c.store.Blob(context.Background(), api.Scope{}, api.BlobReadRequest{ObjectID: actual.Evidence.ID})
	var observation bstate.Observation
	if err != nil || json.Unmarshal(blob.Data, &observation) != nil || observation.ProfileID != profile.ID || observation.LoginID != profile.LoginID || !observation.Available {
		t.Fatal("eligibility cited evidence for a different protected profile")
	}
	again, err := c.service.Eligibility(context.Background(), request)
	if err != nil || !reflect.DeepEqual(actual, again) {
		t.Fatal("unchanged eligibility did not retain stable identity")
	}
	profile.Models = []string{"another-enrolled-model"}
	if err := c.backend.WithBroker(context.Background(), func(j bstate.Journal) error { return j.Write("profile", profile.ID, profile) }); err != nil {
		t.Fatal("cannot change protected compatibility enrollment")
	}
	incompatible, err := c.service.Eligibility(context.Background(), request)
	if err != nil || incompatible.Compatible || incompatible.ID == actual.ID {
		t.Fatal("profile compatibility ignored changed model enrollment")
	}
}

func TestEligibilityGuards(t *testing.T) {
	for _, fault := range []string{"binding", "recovery", "identity", "session", "history", "policy", "paid", "provider", "excluded", "vendor", "runtime", "evidence-origin", "evidence-expiry"} {
		t.Run(fault, func(t *testing.T) {
			c, request, profile := eligibilityCase(t)
			code := api.CodeForbidden
			switch fault {
			case "binding":
				c.store.fail["binding"] = &api.Error{Code: api.CodeNotFound, Owner: "lb-v2-service", Message: "fixture retained binding disappeared"}
				code = api.CodeNotFound
			case "recovery":
				var binding api.LaunchBindingRequest
				if err := c.store.read("binding.json", &binding); err != nil {
					t.Fatal("cannot read eligibility binding control")
				}
				binding.Recovery = nil
				if err := c.store.save("binding.json", binding); err != nil {
					t.Fatal("cannot alter eligibility binding control")
				}
				code = api.CodeIntegrity
			case "identity":
				var binding api.LaunchBindingRequest
				if err := c.store.read("binding.json", &binding); err != nil {
					t.Fatal("cannot read eligibility identity control")
				}
				binding.Identity.CommittedSeq = 0
				if err := c.store.save("binding.json", binding); err != nil {
					t.Fatal("cannot alter eligibility identity control")
				}
				code = api.CodeInvalid
			case "session":
				request.Session.ID = "foreign-session"
				code = api.CodeConflict
			case "history":
				request.Session.HistoryID, request.HistoryID = "foreign-history", "foreign-history"
				code = api.CodeConflict
			case "policy":
				c.store.policy.Generation++
				code = api.CodeConflict
			case "paid":
				c.store.grants.Profiles[1].Paid = true
				c.syncGrants(t)
			case "provider":
				c.store.grants.Profiles[1].Provider = "foreign-provider"
				c.syncGrants(t)
			case "excluded":
				c.store.policy.ProfileExclusions = []api.ID{profile.ID}
			case "vendor":
				profile.VendorVersions = []string{"other-vendor"}
			case "runtime":
				profile.Runtime.SHA256 = digestFixture("different enrolled wrapper")
			case "evidence-origin":
				meta := c.store.objects[profile.Evidence.ID]
				meta.Origin = "lane"
				c.store.objects[meta.Ref.ID] = meta
			case "evidence-expiry":
				c.clock.now = c.clock.now.Add(3 * time.Minute)
			}
			if fault == "vendor" || fault == "runtime" {
				if err := c.backend.WithBroker(context.Background(), func(j bstate.Journal) error { return j.Write("profile", profile.ID, profile) }); err != nil {
					t.Fatal("cannot change compatibility control")
				}
				actual, err := c.service.Eligibility(context.Background(), request)
				if err != nil || actual.Compatible {
					t.Fatal("profile eligibility accepted incompatible retained runtime or vendor")
				}
				return
			}
			_, err := c.service.Eligibility(context.Background(), request)
			stageCode(t, err, code)
		})
	}
}

func TestProtectedRoomGuards(t *testing.T) {
	for _, fault := range []string{"login", "generation", "future", "window", "zone", "producer", "hash", "audience"} {
		t.Run(fault, func(t *testing.T) {
			c := newLaunchCase(t, "helper")
			blob, err := c.store.Blob(context.Background(), api.Scope{}, api.BlobReadRequest{ObjectID: c.profile.Evidence.ID})
			var observation bstate.Observation
			if err != nil || json.Unmarshal(blob.Data, &observation) != nil {
				t.Fatal("cannot decode room evidence control")
			}
			code := api.CodeIntegrity
			switch fault {
			case "login":
				observation.LoginID = "foreign-login"
				code = api.CodeForbidden
			case "generation":
				observation.Generation++
				code = api.CodeForbidden
			case "future":
				observation.CheckedAt = api.Timestamp(c.clock.now.Add(time.Minute).Format(time.RFC3339Nano))
			case "window":
				observation.ExpiresAt = api.Timestamp(c.clock.now.Add(6 * time.Minute).Format(time.RFC3339Nano))
			case "zone":
				observation.CheckedAt = api.Timestamp(c.clock.now.Format("2006-01-02T15:04:05-07:00"))
			case "producer":
				operation := c.store.operations["observation-operation"]
				operation.Status = "running"
				c.store.operations[operation.ID] = operation
				code = api.CodePrerequisite
			case "hash":
				observation.ProfileID = "profile-b"
				changed, err := json.Marshal(observation)
				if err != nil {
					t.Fatal("cannot encode same-length evidence hash control")
				}
				changed, err = api.CanonicalJSON(changed)
				if err != nil || len(changed) != len(blob.Data) {
					t.Fatal("evidence hash control changed its byte length")
				}
				if err := os.WriteFile(filepath.Join(c.store.root, "profile-evidence.blob"), changed, 0600); err != nil {
					t.Fatal("cannot change protected evidence bytes")
				}
			case "audience":
				meta := c.store.objects[c.profile.Evidence.ID]
				meta.ACL.Audience = "lane"
				c.store.objects[meta.Ref.ID] = meta
				code = api.CodeForbidden
			}
			if fault != "producer" && fault != "hash" && fault != "audience" {
				profile := c.profile
				profile.Evidence = c.store.putObject(t, "changed-evidence", "credential_evidence", observation, "observation-operation")
				if err := c.backend.WithBroker(context.Background(), func(j bstate.Journal) error { return j.Write("profile", profile.ID, profile) }); err != nil {
					t.Fatal("cannot set room evidence control")
				}
			}
			_, err = c.service.Room(context.Background(), c.grant)
			stageCode(t, err, code)
		})
	}
}
