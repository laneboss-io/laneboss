package identity

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCurrentScopeRecheck(t *testing.T) {
	s, store, _ := serviceFixture(t)
	initial := fixtureHumanScope(t, s, store)
	connection := initial.Connection.(*fixtureConnection)
	peer := connection.Peer()
	verifier := s.deps.Peers.(*fixturePeers)
	before := verifier.calls
	current, err := s.CurrentConnectionScope(context.Background(), connection)
	if err != nil || current.Actor != initial.Actor || current.Connection != connection || current.PolicyGeneration != initial.PolicyGeneration ||
		connection.Peer() != peer || connection.binds != 1 || verifier.calls != before || before != 1 {
		t.Fatal("bound scope recheck acquired or rebound a peer", err)
	}
	store.policy = &api.EffectivePolicy{Generation: initial.PolicyGeneration + 1}
	current, err = s.CurrentConnectionScope(context.Background(), connection)
	if err != nil || current.PolicyGeneration != store.policy.Generation || connection.Peer() != peer || verifier.calls != before {
		t.Fatal("bound scope recheck ignored current durable authority", err)
	}
	peer.(*fixturePeer).err = errors.New("component peer lifetime ended")
	if _, err := s.CurrentConnectionScope(context.Background(), connection); err == nil || connection.closes != 1 {
		t.Fatal("failed current scope did not close its connection", err)
	}
	if _, err := s.CurrentConnectionScope(context.Background(), nil); err == nil {
		t.Fatal("current scope accepted an absent connection")
	}
}
