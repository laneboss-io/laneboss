package grants

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestMaterializeRecheck(t *testing.T) {
	for _, item := range []struct {
		name   string
		change func(*fixture, *api.GrantSet)
		code   api.ErrorCode
	}{
		{"revoked-parent", func(f *fixture, _ *api.GrantSet) {
			f.updateParent(func(p *api.GrantSet) { p.Revoked = true })
		}, api.CodeForbidden},
		{"policy", func(f *fixture, _ *api.GrantSet) { f.store.policy.Generation++ }, api.CodeConflict},
		{"generation", func(f *fixture, child *api.GrantSet) {
			current := f.store.sets[child.ID]
			current.Generation++
			f.store.sets[child.ID] = current
		}, api.CodeConflict},
		{"expiry", func(f *fixture, _ *api.GrantSet) {
			f.service.deps.Clock = fixedClock{now: f.clock.now.Add(5 * time.Hour)}
		}, api.CodeForbidden},
	} {
		t.Run(item.name, func(t *testing.T) {
			f := newFixture(t)
			child := f.child()
			if _, err := f.service.Revalidate(context.Background(), child); err != nil {
				t.Fatal(err)
			}
			item.change(f, &child)
			_, err := f.service.Materialize(context.Background(), child)
			if f.worker.materializeCalls != 0 {
				t.Fatal("stale authority reached the materialization worker")
			}
			expectCode(t, err, item.code)
		})
	}
}

func TestSourceReadRecheck(t *testing.T) {
	for _, item := range []struct {
		name   string
		change func(*fixture, api.GrantSet)
		code   api.ErrorCode
	}{
		{"parent-revoke", func(f *fixture, _ api.GrantSet) {
			f.updateParent(func(p *api.GrantSet) { p.Revoked = true })
		}, api.CodeForbidden},
		{"self-revoke", func(f *fixture, child api.GrantSet) {
			current := f.store.sets[child.ID]
			current.Revoked = true
			if err := seal(&current); err != nil {
				f.t.Fatal(err)
			}
			f.store.sets[child.ID] = current
		}, api.CodeConflict},
		{"policy", func(f *fixture, _ api.GrantSet) { f.store.policy.Generation++ }, api.CodeConflict},
	} {
		t.Run(item.name, func(t *testing.T) {
			f := newFixture(t)
			child := f.child()
			f.store.onBlob = func() { item.change(f, child) }
			_, err := f.service.Materialize(context.Background(), child)
			if f.store.onBlob != nil {
				t.Fatal("source-read change was not reached")
			}
			if f.worker.materializeCalls != 0 {
				t.Fatal("authority changed during source reads reached the worker")
			}
			expectCode(t, err, item.code)
		})
	}
}

func TestRevokedChain(t *testing.T) {
	f := newFixture(t)
	child := f.child()
	f.updateParent(func(p *api.GrantSet) { p.Revoked = true })
	_, err := f.service.Revalidate(context.Background(), child)
	expectCode(t, err, api.CodeForbidden)
}

func TestChildReadRecheck(t *testing.T) {
	for _, item := range []struct {
		name   string
		change func(*api.Lane)
	}{
		{"run", func(l *api.Lane) { l.Run++ }},
		{"running", func(l *api.Lane) { l.State = "running" }},
		{"stopping", func(l *api.Lane) { l.State = "stopping" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			f := newFixture(t)
			child := f.child()
			request := f.testRequest(child)
			f.store.onBlobObject = request.Candidate.ID
			f.store.onBlob = func() {
				lane := f.store.lanes[child.LifeID]
				item.change(&lane)
				f.store.lanes[child.LifeID] = lane
			}
			_, err := f.service.BoundChildTest(context.Background(), f.scope, request)
			if f.store.onBlob != nil {
				t.Fatal("candidate-read transition was not reached")
			}
			expectCode(t, err, api.CodeConflict)
			if f.worker.testCalls != 0 {
				t.Fatal("changed child run reached the worker")
			}
		})
	}
}
