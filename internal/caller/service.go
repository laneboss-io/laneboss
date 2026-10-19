package caller

import (
	"sync"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/identityd/ticket"
)

// The executable installs the authenticated client here to avoid a dependency
// cycle between caller, lane and the service. A configured service never falls
// back to writable session/role files when the client or socket is unavailable.
var serviceLookup struct {
	sync.RWMutex
	resolve func(*config.Configuration) (Principal, error)
}

func SetServiceResolver(resolve func(*config.Configuration) (Principal, error)) {
	serviceLookup.Lock()
	defer serviceLookup.Unlock()
	serviceLookup.resolve = resolve
}

func resolveService(c *config.Configuration) (Principal, error) {
	serviceLookup.RLock()
	resolve := serviceLookup.resolve
	serviceLookup.RUnlock()
	if resolve == nil {
		return Principal{}, &ticket.Refusal{Reason: ticket.Unavailable}
	}
	return resolve(c)
}

// RequiresTicket also supports an explicitly supplied registrar in isolated Go
// tests. The real client reports configuration through ConfigurationProbe.
func RequiresTicket(c *config.Configuration, registrar ticket.Registrar) bool {
	if _, configured, err := config.IdentityService(c); configured || err != nil {
		return true
	}
	if probe, ok := registrar.(interface {
		ConfiguredFor(*config.Configuration) bool
	}); ok {
		return probe.ConfiguredFor(c)
	}
	if probe, ok := registrar.(ticket.ConfigurationProbe); ok {
		return probe.Configured(c.Name)
	}
	return registrar != nil
}
