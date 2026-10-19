// Package dashboard is owned by lb-v2-dashboard.
// Views require current human connection authority. HTTP actions delegate to
// the installed service dispatcher and fail closed when it is absent.
package dashboard

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	Transport     HumanTransport
	Store         api.StateStore
	Human         api.HumanVerifier
	Identity      api.IdentityAPI
	Authenticator api.Authenticator
	Lifecycle     api.LifecycleAPI
	Messaging     api.MessagingAPI
	Approval      api.ApprovalAPI
	Clock         api.Clock
}

type Service struct {
	deps                Dependencies
	identity            api.IdentityAPI
	auth                api.Authenticator
	mu                  sync.Mutex
	config              string
	origin              string
	host                string
	rpID                string
	enrollmentEndpoint  api.AdminEnrollmentEndpoint
	enrollmentTransport BrowserEnrollmentTransport
	enrollments         map[string]browserEnrollment
	cursorKey           [32]byte
	sessionsByToken     map[string]*browserSession
	sessionsByID        map[api.ID]*browserSession
	revokedSessions     map[api.ID]time.Time
}

func New(deps Dependencies) (*Service, error) {
	if deps.Store == nil || deps.Human == nil || deps.Lifecycle == nil || deps.Messaging == nil || deps.Approval == nil {
		return nil, &api.Error{
			Code:    api.CodePrerequisite,
			Message: "dashboard requires Store, Human, Lifecycle, Messaging and Approval dependencies",
			Instead: "Supply all non-nil dependencies to dashboard.New.",
			Owner:   ownerName,
		}
	}
	idAPI := deps.Identity
	if idAPI == nil {
		if cast, ok := deps.Human.(api.IdentityAPI); ok {
			idAPI = cast
		}
	}
	authAPI := deps.Authenticator
	if authAPI == nil {
		if cast, ok := deps.Human.(api.Authenticator); ok {
			authAPI = cast
		}
	}
	s := &Service{
		deps:            deps,
		identity:        idAPI,
		auth:            authAPI,
		sessionsByToken: make(map[string]*browserSession),
		sessionsByID:    make(map[api.ID]*browserSession),
		revokedSessions: make(map[api.ID]time.Time),
	}
	if _, err := rand.Read(s.cursorKey[:]); err != nil {
		return nil, unavailableErr("failed to initialize cursor authentication key", "Verify OS entropy availability.")
	}
	return s, nil
}

func (s *Service) now() time.Time {
	if s.deps.Clock != nil {
		return s.deps.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

var _ api.DashboardAPI = (*Service)(nil)
var _ api.Module = (*Service)(nil)
var _ http.Handler = (*Service)(nil)

func makeQueryHandler[T any](fn func(context.Context, api.Scope, api.DashboardQuery) (T, error)) api.Handler {
	return func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		var query api.DashboardQuery
		if err := decodeStrictJSON(raw, &query); err != nil {
			return nil, err
		}
		res, err := fn(ctx, scope, query)
		if err != nil {
			return nil, err
		}
		out, err := json.Marshal(res)
		if err != nil {
			return nil, integrityErr("dashboard response could not be encoded", "Inspect the view payload.")
		}
		return out, nil
	}
}

func (s *Service) Register(registry api.Registrar) error {
	if s == nil || registry == nil {
		return invalidErr("dashboard service and registrar are required", "Pass a non-nil Registrar to dashboard.Register.")
	}
	routes := []struct {
		method  api.Method
		handler api.Handler
	}{
		{"dashboard.tree", makeQueryHandler(s.DashboardTree)},
		{"dashboard.raw", makeQueryHandler(s.DashboardRaw)},
		{"dashboard.decisions", makeQueryHandler(s.DashboardDecisions)},
		{"dashboard.refusals", makeQueryHandler(s.DashboardRefusals)},
		{"dashboard.plugins", makeQueryHandler(s.DashboardPlugins)},
		{"dashboard.resources", makeQueryHandler(s.DashboardResources)},
		{"dashboard.lifecycle", makeQueryHandler(s.DashboardLifecycle)},
		{"dashboard.approvals", makeQueryHandler(s.DashboardApprovals)},
	}
	for _, r := range routes {
		if err := registry.Register(r.method, r.handler); err != nil {
			return err
		}
	}
	return nil
}
