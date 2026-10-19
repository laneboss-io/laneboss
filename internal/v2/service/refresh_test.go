package service

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
	"net"
	"testing"
	"time"
)

func TestReadAuthorityRefresh(t *testing.T) {
	for _, fault := range []string{"valid", "principal", "absolute_expiry", "stale_revision", "rebind"} {
		t.Run(fault, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			c, err := newConnection(a, api.InstalledBinding{Config: "service-fixture", Class: api.EndpointHuman, EndpointGeneration: 1}, fixtureClock{})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := c.BindPeer(&peerFixture{facts: api.PeerFacts{HostUID: 101, HostPID: 123, ProcessGeneration: "one"}}); err != nil {
				t.Fatal(err)
			}
			before := api.ReadAuthority{ConnectionID: c.ID(), SessionID: fixtureID(t), PrincipalID: fixtureID(t), CredentialID: fixtureID(t), Config: "service-fixture", EndpointGeneration: 1, Generation: 1, IdleExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano))}
			if err := c.BindReadAuthority(before); err != nil {
				t.Fatal(err)
			}
			if fault == "rebind" {
				if err := c.BindReadAuthority(before); err == nil {
					t.Fatal("transport rebound a one use read authority")
				}
				return
			}
			after := before
			after.Generation++
			after.IdleExpiresAt = api.Timestamp(time.Now().Add(4 * time.Minute).UTC().Format(time.RFC3339Nano))
			switch fault {
			case "principal":
				after.PrincipalID = fixtureID(t)
			case "absolute_expiry":
				after.ExpiresAt = api.Timestamp(time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339Nano))
			case "stale_revision":
				after.Generation++
			}
			err = c.RefreshReadAuthority(context.Background(), api.ReadAuthorityUpdate{Before: before, After: after})
			if fault == "valid" {
				actual, readErr := c.ReadAuthority(context.Background())
				if err != nil || readErr != nil || actual != after {
					t.Fatal("committed read authority refresh did not replace the same session", err, readErr)
				}
				return
			}
			if err == nil {
				t.Fatal("transport refresh accepted " + fault)
			}
			if _, err := c.ReadAuthority(context.Background()); err == nil {
				t.Fatal("failed transport refresh left the connection usable")
			}
		})
	}
}
