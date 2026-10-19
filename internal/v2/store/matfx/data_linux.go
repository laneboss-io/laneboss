//go:build linux

// Package matfx binds the real grants resolver to shared data fixtures
// without making the base store fixture depend on the grants service.
package matfx

import (
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// NewData retains the fixture's real reserved grant issuance and store path.
func NewData(t testing.TB, options ...fx.DataOptions) *fx.DataFixture {
	t.Helper()
	return fx.NewDataWithResolver(t, func(f *fx.Fixture) (api.GrantResolver, error) {
		return grants.New(grants.Dependencies{Config: f.Deps.Config, Store: f.State, Worker: &dataFixtureWorker{}, Clock: f.Deps.Clock})
	}, options...)
}

type dataFixtureWorker struct{ api.DataWorker }
