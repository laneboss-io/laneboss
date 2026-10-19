package api

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestIssuedLaunchProfileMapping(t *testing.T) {
	for _, mode := range []string{"start", "adopt"} {
		for _, driver := range []Driver{DriverCodex, DriverClaudock} {
			t.Run(mode+"/"+string(driver), func(t *testing.T) {
				requested := []ProfileDelegation{{ParentGrantID: "template-one", ProfileID: "provider-one", ExpiresAt: "2030-01-01T00:00:00Z"},
					{ParentGrantID: "template-two", ProfileID: "provider-two", Delegate: true, ExpiresAt: "2030-01-01T00:00:00Z"}}
				grants := GrantRequest{Resources: []ResourceDelegation{}, Data: []DataGrantRequest{}, Secrets: []SecretDelegation{},
					Profiles: requested, Network: []NetworkDelegation{}, Channels: []ChannelDelegation{}}
				var body any = StartRequest{ProfileGrantID: "template-two", Grants: grants}
				if mode == "adopt" {
					body = AdoptRequest{ProfileGrantID: "template-two", Grants: grants}
				}
				raw, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				frame := Request{Protocol: Protocol, Schema: SchemaVersion, Config: "profile-mapping", Method: Method("lane." + mode), RequestID: "original-request", IdempotencyKey: "original-key", Params: raw}
				frame.RequestSHA256, err = RequestDigest(frame)
				if err != nil {
					t.Fatal(err)
				}
				r := LaunchReservation{ID: "reservation", Config: frame.Config, Mode: mode, Driver: driver, Target: LifeRef{LifeID: "life", Run: 1},
					GrantSetID: "issued-set", PolicyGeneration: 1, RequestID: frame.RequestID, RequestSHA256: frame.RequestSHA256}
				issued := GrantSet{ID: r.GrantSetID, LifeID: r.Target.LifeID, PolicyGeneration: 1, Profiles: []ProfileGrant{
					{ID: "issued-one", ProfileID: "provider-one", Driver: driver, ExpiresAt: requested[0].ExpiresAt},
					{ID: "issued-two", ProfileID: "provider-two", Driver: driver, Delegate: true, ExpiresAt: requested[1].ExpiresAt}}}
				before := append([]byte{}, frame.Params...)
				mapped, err := IssuedLaunchProfile(r, frame, issued)
				if err != nil || mapped != issued.Profiles[1] || mapped.ID == requested[1].ParentGrantID || !bytes.Equal(frame.Params, before) {
					t.Fatal("mapping selected by driver or rewrote request-side member identity", err)
				}
				r.ParentLifeID, issued.ParentLifeID = "parent-life", "parent-life"
				issued.Profiles[0].ParentGrantID, issued.Profiles[1].ParentGrantID = requested[0].ParentGrantID, requested[1].ParentGrantID
				mapped, err = IssuedLaunchProfile(r, frame, issued)
				if err != nil || mapped != issued.Profiles[1] {
					t.Fatal("child mapping lost its actual delegation parent", err)
				}
				issued.Profiles[1].ParentGrantID = "foreign-template"
				if _, err := IssuedLaunchProfile(r, frame, issued); err == nil {
					t.Fatal("child mapping accepted another template's member")
				}
			})
		}
	}
}
