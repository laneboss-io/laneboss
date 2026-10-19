package lifecycle

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestRootPolicyBeforeTicket(t *testing.T) {
	f := newLaunchFixture(t)
	f.request.RootTicketID = "root-policy-ticket"
	human := api.Actor{Kind: "human", ID: "root-controller"}
	ticket := api.Ticket{ID: f.request.RootTicketID, PrincipalID: human.ID, Config: "example", EndpointGeneration: 1,
		Level: f.request.Level, Role: f.request.Role, GrantSetID: "root-policy-grants", ExpiresAt: "2031-01-01T00:00:00Z"}
	f.store.tickets[ticket.ID] = ticket
	grants := launchClone(t, f.ports.delegated)
	grants.ID = ticket.GrantSetID
	f.store.grants[grants.ID] = grants
	scope := f.fixture.scope("lane.start", f.request, human)
	advanceFixturePolicy(f.fixture)
	_, err := f.service.LaneStart(context.Background(), scope, f.request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict || f.store.reservationCalls != 0 ||
		len(f.store.plans) != 0 || !reflect.DeepEqual(f.store.tickets[ticket.ID], ticket) {
		t.Fatalf("stale root policy consumed its ticket reservation: %v", err)
	}
}
